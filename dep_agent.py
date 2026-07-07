"""Dependency Intelligence Agent.

Three-layer dependency discovery:

  Layer 1 — Known catalogue (35+ products with precise constraints)
             Fast lookup; covers Splunk, Dynatrace, Bitbucket, Jenkins, etc.

  Layer 2 — RPM dependency graph (automatic, OS-level)
             `rpm -q --whatrequires <pkg>` finds EVERY installed RPM that links
             to the vulnerable library — no catalogue entry needed.

  Layer 3 — LLM gap-filling
             For running services not covered by layers 1 or 2 (custom apps,
             JARs, Python services, containers), the LLM reasons about whether
             the service likely depends on the vulnerable package.

Risk levels (worst-first):
  AT_RISK        — upgrade would break a running product
  CHECK_VERSION  — product depends on this; verify target version is in range
  VENDOR_BUNDLED — product ships its own copy; OS patch won't help the product
  SAFE           — no running product depends on this package

Usage:
  python dep_agent.py report.json [--ait-id AIT-001] [--dry]
  python dep_agent.py --live [--ait-id AIT-001]   # SSH to target + discover live
"""

import datetime
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

from config import SSH_USER, TARGET_HOST, ssh_opts
from llm_client import generate
from remediation_core import parse_trivy

# ---------------------------------------------------------------------------
# Layer 1 — Known product catalogue (35+ products)
# ---------------------------------------------------------------------------
# Each entry:
#   label           — human-readable product name
#   detect_paths    — filesystem paths that confirm the product is installed
#   detect_services — systemd service names to check
#   version_cmd     — shell command to extract product version (run on target)
#   dependencies    — {pkg_key: {constraint, type, note}}
#       constraint  — semver range string or None
#       type        — "system" (OS-managed) or "bundled" (product ships its own)
#       note        — remediation note shown to the operator

KNOWN_PRODUCTS: dict[str, dict] = {
    # ── Monitoring / APM ─────────────────────────────────────────────────────
    "splunk-forwarder": {
        "label": "Splunk Universal Forwarder",
        "detect_paths": ["/opt/splunkforwarder/bin/splunk", "/opt/splunk/bin/splunk"],
        "detect_services": ["SplunkForwarder", "splunkd"],
        "version_cmd": "(/opt/splunkforwarder/bin/splunk version 2>/dev/null || /opt/splunk/bin/splunk version 2>/dev/null) | head -1",
        "dependencies": {
            "openssl":    {"constraint": ">=1.0.2", "type": "system",
                           "note": "Splunk links against system OpenSSL for TLS. Safe to patch if target >=1.0.2; restart SplunkForwarder after patching."},
            "libssl":     {"constraint": ">=1.0.2", "type": "system",
                           "note": "System libssl used by Splunk for TLS. Restart SplunkForwarder after patching."},
            "python3":    {"constraint": None, "type": "bundled",
                           "note": "Splunk 8.x/9.x ships its own embedded Python. OS python3 CVEs do NOT affect Splunk internals. Update Splunk itself for bundled Python CVEs."},
            "log4j":      {"constraint": None, "type": "bundled",
                           "note": "Older Splunk versions bundle log4j. OS log4j patches won't reach Splunk internals. Check Splunk Security Advisory and upgrade Splunk."},
            "log4j-core": {"constraint": None, "type": "bundled",
                           "note": "log4j-core is bundled inside Splunk JARs. Patch Splunk itself — dnf/rpm cannot reach Splunk's internal JARs."},
        },
    },
    "dynatrace-oneagent": {
        "label": "Dynatrace OneAgent",
        "detect_paths": ["/opt/dynatrace/oneagent/agent/bin/oneagentd", "/opt/dynatrace/oneagent"],
        "detect_services": ["oneagent", "dynatraceoneagent"],
        "version_cmd": "cat /opt/dynatrace/oneagent/agent/conf/version 2>/dev/null | head -1",
        "dependencies": {
            "glibc":   {"constraint": ">=2.17", "type": "system",
                        "note": "OneAgent requires glibc >=2.17. RHEL8 ships 2.28 — all glibc patches within 2.x are safe. Restart oneagent after patching."},
            "openssl": {"constraint": None, "type": "bundled",
                        "note": "Dynatrace bundles its own SSL stack. System openssl/libssl patches are safe independently."},
            "libssl":  {"constraint": None, "type": "bundled",
                        "note": "Dynatrace bundles its own SSL stack. System libssl patches are safe."},
        },
    },
    "datadog-agent": {
        "label": "Datadog Agent",
        "detect_paths": ["/opt/datadog-agent/bin/agent/agent", "/etc/datadog-agent"],
        "detect_services": ["datadog-agent", "dd-agent"],
        "version_cmd": "/opt/datadog-agent/bin/agent/agent version 2>/dev/null | head -1",
        "dependencies": {
            "python3":  {"constraint": None, "type": "bundled",
                         "note": "Datadog Agent 6+ ships its own embedded Python 3. OS python3 patches do not affect the agent. Upgrade the agent itself for Python CVEs."},
            "openssl":  {"constraint": None, "type": "bundled",
                         "note": "Datadog Agent bundles its own OpenSSL. System openssl patches are safe."},
        },
    },
    "newrelic-agent": {
        "label": "New Relic Infrastructure Agent",
        "detect_paths": ["/var/db/newrelic-infra", "/etc/newrelic-infra.yml"],
        "detect_services": ["newrelic-infra"],
        "version_cmd": "/usr/bin/newrelic-infra -version 2>/dev/null | head -1",
        "dependencies": {
            "glibc":  {"constraint": ">=2.17", "type": "system",
                       "note": "New Relic infra agent requires system glibc. Upgrade is safe on RHEL8; restart newrelic-infra after patching."},
        },
    },
    "appdynamics-agent": {
        "label": "AppDynamics Machine Agent",
        "detect_paths": ["/opt/appdynamics/machine-agent", "/opt/appdynamics"],
        "detect_services": ["appdynamics-machine-agent"],
        "version_cmd": None,
        "dependencies": {
            "java-11-openjdk": {"constraint": ">=11", "type": "system",
                                "note": "AppDynamics Machine Agent requires Java 11+. Patch within 11.x or 17.x is safe."},
            "java-17-openjdk": {"constraint": ">=17", "type": "system",
                                "note": "AppDynamics Machine Agent on Java 17 — patch within 17.x is safe."},
        },
    },
    "zabbix-agent": {
        "label": "Zabbix Agent",
        "detect_paths": ["/usr/sbin/zabbix_agent2", "/etc/zabbix/zabbix_agentd.conf"],
        "detect_services": ["zabbix-agent", "zabbix-agent2"],
        "version_cmd": "zabbix_agent2 -V 2>/dev/null | head -1 || zabbix_agentd -V 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "Zabbix Agent links to system OpenSSL. Patch is safe; restart zabbix-agent after patching."},
        },
    },
    "prometheus": {
        "label": "Prometheus",
        "detect_paths": ["/usr/bin/prometheus", "/opt/prometheus"],
        "detect_services": ["prometheus"],
        "version_cmd": "prometheus --version 2>&1 | head -1",
        "dependencies": {
            "glibc": {"constraint": ">=2.17", "type": "system",
                      "note": "Prometheus is a Go binary statically linked. glibc patches are safe — no restart required."},
        },
    },
    "grafana": {
        "label": "Grafana",
        "detect_paths": ["/usr/sbin/grafana-server", "/etc/grafana"],
        "detect_services": ["grafana-server", "grafana"],
        "version_cmd": "grafana-server -v 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "Grafana links to system OpenSSL for HTTPS. Patch is safe; restart grafana-server after patching."},
        },
    },

    # ── Atlassian suite ───────────────────────────────────────────────────────
    "bitbucket": {
        "label": "Atlassian Bitbucket",
        "detect_paths": ["/opt/atlassian/bitbucket", "/opt/bitbucket",
                         "/var/atlassian/application-data/bitbucket"],
        "detect_services": ["atlbitbucket", "bitbucket"],
        "version_cmd": "cat /opt/atlassian/bitbucket/current/app/WEB-INF/classes/bitbucket-build.properties 2>/dev/null | grep 'bitbucket.version' | head -1",
        "dependencies": {
            "git":                {"constraint": ">=2.17.0", "type": "system",
                                   "note": "Bitbucket requires git >=2.17.0 on PATH. Verify the patched version satisfies this."},
            "java-11-openjdk":    {"constraint": ">=11,<21", "type": "system",
                                   "note": "Bitbucket 8.x requires Java 11 LTS; Bitbucket 9.x supports Java 17. Patch within the supported major version."},
            "java-17-openjdk":    {"constraint": ">=17,<21", "type": "system",
                                   "note": "Bitbucket 9.x on Java 17 — patch within 17.x is safe."},
            "java-1.8.0-openjdk": {"constraint": None, "type": "system",
                                   "note": "Bitbucket no longer supports Java 8. Migrate to Java 11 or 17 as part of a Bitbucket upgrade."},
        },
    },
    "confluence": {
        "label": "Atlassian Confluence",
        "detect_paths": ["/opt/atlassian/confluence",
                         "/var/atlassian/application-data/confluence"],
        "detect_services": ["atlconfluence", "confluence"],
        "version_cmd": None,
        "dependencies": {
            "java-11-openjdk":    {"constraint": ">=11,<17", "type": "system",
                                   "note": "Confluence LTS requires Java 11. Do not jump to Java 17 without first upgrading Confluence to a version that supports it."},
            "java-1.8.0-openjdk": {"constraint": None, "type": "system",
                                   "note": "Confluence dropped Java 8. Migration to Java 11 is required."},
        },
    },
    "jira": {
        "label": "Atlassian Jira",
        "detect_paths": ["/opt/atlassian/jira",
                         "/var/atlassian/application-data/jira"],
        "detect_services": ["atljira", "jira"],
        "version_cmd": None,
        "dependencies": {
            "java-11-openjdk":    {"constraint": ">=11,<17", "type": "system",
                                   "note": "Jira Software LTS requires Java 11. Patch within 11.x is safe."},
            "java-1.8.0-openjdk": {"constraint": None, "type": "system",
                                   "note": "Jira dropped Java 8. Plan migration to Java 11."},
        },
    },

    # ── CI/CD / Dev tooling ───────────────────────────────────────────────────
    "jenkins": {
        "label": "Jenkins CI",
        "detect_paths": ["/var/lib/jenkins/jenkins.war", "/opt/jenkins",
                         "/usr/share/jenkins"],
        "detect_services": ["jenkins"],
        "version_cmd": "java -jar /var/lib/jenkins/jenkins.war --version 2>/dev/null || cat /var/lib/jenkins/config.xml 2>/dev/null | grep '<version>' | head -1",
        "dependencies": {
            "java-11-openjdk": {"constraint": ">=11", "type": "system",
                                "note": "Jenkins LTS supports Java 11 and 17. Patch within 11.x or 17.x is safe."},
            "java-17-openjdk": {"constraint": ">=17", "type": "system",
                                "note": "Jenkins on Java 17 — patch within 17.x is safe."},
            "git":             {"constraint": ">=2.7.0", "type": "system",
                                "note": "Jenkins Git plugin requires git on PATH. Upgrade is safe as long as target is >=2.7.0."},
        },
    },
    "gitlab": {
        "label": "GitLab",
        "detect_paths": ["/opt/gitlab/bin/gitlab-ctl", "/etc/gitlab/gitlab.rb"],
        "detect_services": ["gitlab-runsvdir"],
        "version_cmd": "/opt/gitlab/bin/gitlab-ctl version 2>/dev/null | head -1",
        "dependencies": {
            "git":     {"constraint": ">=2.17.0", "type": "bundled",
                        "note": "GitLab Omnibus bundles its own git. OS git patches don't affect GitLab — upgrade GitLab itself."},
            "openssl": {"constraint": None, "type": "bundled",
                        "note": "GitLab Omnibus bundles its own OpenSSL. System openssl patches are safe independently."},
            "python3": {"constraint": None, "type": "bundled",
                        "note": "GitLab Omnibus bundles its own Python. OS python3 patches don't affect GitLab."},
        },
    },
    "nexus": {
        "label": "Sonatype Nexus Repository",
        "detect_paths": ["/opt/nexus", "/opt/sonatype/nexus", "/opt/sonatype-work"],
        "detect_services": ["nexus"],
        "version_cmd": None,
        "dependencies": {
            "java-11-openjdk": {"constraint": ">=11,<17", "type": "system",
                                "note": "Nexus Repository 3.x requires Java 11. Patch within 11.x is safe."},
        },
    },
    "sonarqube": {
        "label": "SonarQube",
        "detect_paths": ["/opt/sonarqube", "/opt/sonar"],
        "detect_services": ["sonarqube", "sonar"],
        "version_cmd": None,
        "dependencies": {
            "java-11-openjdk": {"constraint": ">=11,<17", "type": "system",
                                "note": "SonarQube 9.x requires Java 11. Patch within 11.x is safe."},
            "java-17-openjdk": {"constraint": ">=17", "type": "system",
                                "note": "SonarQube 10.x supports Java 17. Patch within 17.x is safe."},
            "elasticsearch":   {"constraint": None, "type": "bundled",
                                "note": "SonarQube bundles its own Elasticsearch. System elasticsearch patches don't apply."},
        },
    },

    # ── Web servers / Proxies ─────────────────────────────────────────────────
    "nginx": {
        "label": "NGINX",
        "detect_paths": ["/usr/sbin/nginx", "/etc/nginx/nginx.conf"],
        "detect_services": ["nginx"],
        "version_cmd": "nginx -v 2>&1 | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "nginx links to system OpenSSL. Patch is safe; restart nginx (not just reload) to load the updated library."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "nginx loads libssl at startup. Full restart required after libssl patch."},
            "pcre":    {"constraint": ">=8.32", "type": "system",
                        "note": "nginx links to system PCRE for regex URI matching. Upgrade is safe; restart nginx."},
        },
    },
    "httpd": {
        "label": "Apache httpd",
        "detect_paths": ["/usr/sbin/httpd", "/etc/httpd/conf/httpd.conf"],
        "detect_services": ["httpd"],
        "version_cmd": "httpd -v 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "Apache httpd mod_ssl links to system OpenSSL. Patch is safe; restart httpd after patching."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "mod_ssl loads libssl at startup. Restart httpd after libssl patch."},
            "apr":     {"constraint": ">=1.5.0", "type": "system",
                        "note": "httpd links to the Apache Portable Runtime (APR). Patch is safe; restart httpd."},
        },
    },
    "haproxy": {
        "label": "HAProxy",
        "detect_paths": ["/usr/sbin/haproxy", "/etc/haproxy/haproxy.cfg"],
        "detect_services": ["haproxy"],
        "version_cmd": "haproxy -v 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "HAProxy links to system OpenSSL for SSL termination. Patch is safe; restart haproxy after patching."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "HAProxy loads libssl at startup. Restart haproxy after libssl patch."},
        },
    },

    # ── App servers ───────────────────────────────────────────────────────────
    "tomcat": {
        "label": "Apache Tomcat",
        "detect_paths": ["/opt/tomcat", "/usr/share/tomcat", "/opt/apache-tomcat"],
        "detect_services": ["tomcat", "tomcat9", "tomcat10"],
        "version_cmd": "catalina.sh version 2>/dev/null | grep 'Server version' | head -1",
        "dependencies": {
            "java-11-openjdk": {"constraint": ">=11", "type": "system",
                                "note": "Tomcat 9.x/10.x supports Java 11+. Patch within 11.x or 17.x is safe."},
            "java-17-openjdk": {"constraint": ">=17", "type": "system",
                                "note": "Tomcat 10.x on Java 17 — patch within 17.x is safe."},
        },
    },
    "jboss-wildfly": {
        "label": "JBoss / WildFly",
        "detect_paths": ["/opt/jboss", "/opt/wildfly", "/opt/jboss-eap"],
        "detect_services": ["jboss", "wildfly", "eap7"],
        "version_cmd": None,
        "dependencies": {
            "java-11-openjdk": {"constraint": ">=11", "type": "system",
                                "note": "WildFly 23+ / JBoss EAP 7.4+ requires Java 11+. Patch within 11.x or 17.x is safe."},
            "java-1.8.0-openjdk": {"constraint": ">=8", "type": "system",
                                   "note": "Older JBoss/EAP versions support Java 8. Patch within 8.x is safe; verify EAP version support matrix for Java 11."},
        },
    },

    # ── Databases ─────────────────────────────────────────────────────────────
    "postgresql": {
        "label": "PostgreSQL",
        "detect_paths": ["/var/lib/pgsql", "/usr/bin/postgres"],
        "detect_services": ["postgresql", "postgresql-14", "postgresql-15", "postgresql-16"],
        "version_cmd": "psql --version 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "PostgreSQL links to system OpenSSL for SSL connections. Patch is safe; restart postgresql after patching."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "Same as openssl. Restart postgresql after libssl patch."},
            "glibc":   {"constraint": ">=2.17", "type": "system",
                        "note": "PostgreSQL requires glibc. RHEL8 ships 2.28 — all patches are safe; restart postgresql."},
        },
    },
    "mysql": {
        "label": "MySQL / MariaDB",
        "detect_paths": ["/usr/bin/mysqld", "/var/lib/mysql"],
        "detect_services": ["mysqld", "mysql", "mariadb"],
        "version_cmd": "mysqld --version 2>/dev/null | head -1 || mariadbd --version 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "MySQL/MariaDB links to system OpenSSL for TLS connections. Patch is safe; restart mysqld after patching."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "Restart mysqld after libssl patch."},
        },
    },
    "redis": {
        "label": "Redis",
        "detect_paths": ["/usr/bin/redis-server", "/etc/redis/redis.conf"],
        "detect_services": ["redis", "redis-server"],
        "version_cmd": "redis-server --version 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.0.2", "type": "system",
                        "note": "Redis (TLS mode) links to system OpenSSL. Patch is safe; restart redis after patching."},
        },
    },
    "mongodb": {
        "label": "MongoDB",
        "detect_paths": ["/usr/bin/mongod", "/var/lib/mongo"],
        "detect_services": ["mongod", "mongodb"],
        "version_cmd": "mongod --version 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "MongoDB links to system OpenSSL for TLS. Patch is safe; restart mongod after patching."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "Same as openssl. Restart mongod after libssl patch."},
        },
    },
    "elasticsearch": {
        "label": "Elasticsearch / OpenSearch",
        "detect_paths": ["/usr/share/elasticsearch", "/opt/elasticsearch",
                         "/usr/share/opensearch"],
        "detect_services": ["elasticsearch", "opensearch"],
        "version_cmd": "cat /usr/share/elasticsearch/version 2>/dev/null | head -1",
        "dependencies": {
            "java-11-openjdk": {"constraint": None, "type": "bundled",
                                "note": "Elasticsearch 7.x+ bundles its own JDK. OS Java patches do not affect it. Upgrade Elasticsearch to patch the bundled JDK."},
            "java-17-openjdk": {"constraint": None, "type": "bundled",
                                "note": "Elasticsearch 8.x bundles JDK 17. OS Java patches do not affect it."},
        },
    },

    # ── Message brokers ───────────────────────────────────────────────────────
    "rabbitmq": {
        "label": "RabbitMQ",
        "detect_paths": ["/usr/lib/rabbitmq", "/etc/rabbitmq/rabbitmq.conf"],
        "detect_services": ["rabbitmq-server"],
        "version_cmd": "rabbitmqctl version 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "RabbitMQ (Erlang) links to system OpenSSL for TLS. Patch is safe; restart rabbitmq-server after patching."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "Same as openssl. Restart rabbitmq-server after patching."},
        },
    },
    "kafka": {
        "label": "Apache Kafka",
        "detect_paths": ["/opt/kafka", "/usr/share/kafka"],
        "detect_services": ["kafka", "kafka-server"],
        "version_cmd": None,
        "dependencies": {
            "java-11-openjdk": {"constraint": ">=11", "type": "system",
                                "note": "Kafka 3.x requires Java 11+. Patch within 11.x or 17.x is safe; restart kafka after patching."},
            "java-17-openjdk": {"constraint": ">=17", "type": "system",
                                "note": "Kafka on Java 17 — patch within 17.x is safe."},
        },
    },

    # ── Security / Infrastructure ─────────────────────────────────────────────
    "vault": {
        "label": "HashiCorp Vault",
        "detect_paths": ["/usr/bin/vault", "/opt/vault"],
        "detect_services": ["vault"],
        "version_cmd": "vault version 2>/dev/null | head -1",
        "dependencies": {
            "glibc": {"constraint": ">=2.17", "type": "system",
                      "note": "Vault is a Go binary — glibc patches are safe. Restart vault after patching."},
        },
    },
    "consul": {
        "label": "HashiCorp Consul",
        "detect_paths": ["/usr/bin/consul", "/opt/consul"],
        "detect_services": ["consul"],
        "version_cmd": "consul version 2>/dev/null | head -1",
        "dependencies": {
            "glibc": {"constraint": ">=2.17", "type": "system",
                      "note": "Consul is a Go binary — glibc patches are safe. Restart consul after patching."},
        },
    },
    "puppet-agent": {
        "label": "Puppet Agent",
        "detect_paths": ["/opt/puppetlabs/puppet/bin/puppet", "/etc/puppetlabs/puppet"],
        "detect_services": ["puppet"],
        "version_cmd": "/opt/puppetlabs/puppet/bin/puppet --version 2>/dev/null | head -1",
        "dependencies": {
            "ruby":    {"constraint": None, "type": "bundled",
                        "note": "Puppet Agent bundles its own Ruby runtime. OS ruby patches do not affect Puppet. Upgrade via puppetlabs repos."},
            "openssl": {"constraint": None, "type": "bundled",
                        "note": "Puppet Agent bundles its own OpenSSL. System openssl patches are safe independently."},
        },
    },
    "ansible-awx": {
        "label": "Ansible AWX / Automation Platform",
        "detect_paths": ["/var/lib/awx", "/usr/bin/awx-manage"],
        "detect_services": ["awx-uwsgi", "awx-daphne"],
        "version_cmd": "awx-manage version 2>/dev/null | head -1",
        "dependencies": {
            "python3": {"constraint": ">=3.9", "type": "system",
                        "note": "AWX uses system Python 3 for task execution. Patch within the installed minor version is safe; restart AWX services after patching."},
        },
    },
    "php-fpm": {
        "label": "PHP-FPM",
        "detect_paths": ["/etc/php-fpm.conf", "/usr/sbin/php-fpm"],
        "detect_services": ["php-fpm", "php7.4-fpm", "php8.1-fpm", "php8.2-fpm"],
        "version_cmd": "php --version 2>/dev/null | head -1",
        "dependencies": {
            "openssl": {"constraint": ">=1.1.1", "type": "system",
                        "note": "PHP-FPM links to system OpenSSL. Patch is safe; restart php-fpm after patching."},
            "libssl":  {"constraint": ">=1.1.1", "type": "system",
                        "note": "Same as openssl. Restart php-fpm after libssl patch."},
        },
    },
}

RISK_LEVELS = {
    "AT_RISK":        {"label": "At Risk",        "color": "red",   "icon": "🔴", "priority": 0},
    "CHECK_VERSION":  {"label": "Check Version",  "color": "amber", "icon": "🟡", "priority": 1},
    "VENDOR_BUNDLED": {"label": "Vendor Bundled", "color": "blue",  "icon": "📦", "priority": 2},
    "SAFE":           {"label": "Safe to Patch",  "color": "green", "icon": "🟢", "priority": 3},
    "UNKNOWN":        {"label": "Not Checked",    "color": "grey",  "icon": "⬜", "priority": 4},
}

# Map RPM package name patterns → friendly service label (for RPM layer output)
_RPM_SERVICE_LABELS = {
    "nginx":            "NGINX",
    "httpd":            "Apache httpd",
    "haproxy":          "HAProxy",
    "postgresql":       "PostgreSQL",
    "mysql":            "MySQL",
    "mariadb":          "MariaDB",
    "redis":            "Redis",
    "mongodb":          "MongoDB",
    "rabbitmq-server":  "RabbitMQ",
    "openssh-server":   "SSH daemon",
    "curl":             "curl / libcurl",
    "libcurl":          "curl / libcurl",
    "java":             "System Java",
    "php":              "PHP",
    "php-fpm":          "PHP-FPM",
    "python3":          "Python 3 runtime",
    "python2":          "Python 2 runtime",
    "ruby":             "Ruby runtime",
    "nodejs":           "Node.js runtime",
}


# ---------------------------------------------------------------------------
# Package name normalization
# ---------------------------------------------------------------------------

def _normalize_pkg(pkg: str) -> list[str]:
    """Return candidate keys to match against product dependency dicts."""
    lower = pkg.lower()
    if ":" in lower:                         # Maven group:artifact → artifact
        lower = lower.split(":")[-1]
    lower = re.sub(r'^\d+:', '', lower)      # strip RPM epoch
    base  = re.sub(r'[-_]\d+.*$', '', lower) # strip version suffix
    candidates = [lower, base, base.replace("-", "_"), base.replace("_", "-")]
    if any(k in lower for k in ("java", "jdk", "jre", "openjdk")):
        for v in ("8", "11", "17", "21"):
            candidates += [f"java-{v}-openjdk", f"java-{v}.0-openjdk", f"openjdk-{v}"]
    return list(dict.fromkeys(candidates))


# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------

def _ssh_run(host: str, user: str, opts: list, cmd: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            ["ssh"] + opts + [f"{user}@{host}", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout.strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Layer 1 — catalogue discovery
# ---------------------------------------------------------------------------

def _discover_catalogue(host: str, user: str, opts: list,
                         running_svcs: set) -> dict[str, dict]:
    """Detect which catalogue products are installed + running on the target."""
    detected: dict[str, dict] = {}

    checks = []
    for key, prod in KNOWN_PRODUCTS.items():
        for path in prod["detect_paths"]:
            checks.append(f"[ -e '{path}' ] && echo '{key}:{path}'")

    raw = _ssh_run(host, user, opts, " ; ".join(checks), timeout=25)
    found_paths: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            k, p = line.split(":", 1)
            found_paths[k.strip()] = p.strip()

    for key, prod in KNOWN_PRODUCTS.items():
        path_hit = found_paths.get(key)
        svc_hit  = next((s for s in prod["detect_services"] if s in running_svcs), None)
        if not path_hit and not svc_hit:
            continue

        version = ""
        if prod.get("version_cmd"):
            raw_ver = _ssh_run(host, user, opts, prod["version_cmd"], timeout=8)
            m = re.search(r'[\d]+\.[\d]+[\.\d]*', raw_ver)
            version = m.group(0) if m else raw_ver[:40]

        detected[key] = {
            "label":           prod["label"],
            "version":         version,
            "install_path":    path_hit or "",
            "service_running": svc_hit or "",
            "layer":           "catalogue",
        }
        print(f"  [L1-catalogue] {prod['label']} {version}")

    return detected


# ---------------------------------------------------------------------------
# Layer 2 — RPM dependency graph
# ---------------------------------------------------------------------------

def _discover_rpm_dependents(host: str, user: str, opts: list,
                              pkg_names: list[str]) -> dict[str, dict]:
    """For each vulnerable package, run `rpm -q --whatrequires` to find which
    installed RPMs depend on it.  Returns {rpm_pkg: {label, dependents, layer}}.

    This catches ANY service installed via RPM, even if not in the catalogue.
    """
    dependents: dict[str, set] = defaultdict(set)  # rpm_pkg → set of vulnerable_pkgs it depends on

    for pkg in pkg_names:
        # Try with and without -libs suffix (openssl → openssl-libs)
        for query in [pkg, f"{pkg}-libs", f"lib{pkg}"]:
            out = _ssh_run(
                host, user, opts,
                f"rpm -q --whatrequires '{query}' --qf '%{{NAME}}\\n' 2>/dev/null",
                timeout=10,
            )
            for line in out.splitlines():
                dep = line.strip()
                if dep and not dep.startswith("no package"):
                    dependents[dep].add(pkg)
            if dependents:
                break  # found results with this query form

    result: dict[str, dict] = {}
    for rpm_pkg, vuln_pkgs in dependents.items():
        label = _RPM_SERVICE_LABELS.get(rpm_pkg)
        if not label:
            # Derive label from RPM name (strip version, arch)
            label = rpm_pkg.replace("-", " ").replace("_", " ").title()
        result[rpm_pkg] = {
            "label":        label,
            "version":      "",
            "install_path": "",
            "service_running": "",
            "depends_on":   sorted(vuln_pkgs),  # which vulnerable pkgs this RPM needs
            "layer":        "rpm-graph",
        }
        print(f"  [L2-rpm-graph] {label} depends on: {', '.join(sorted(vuln_pkgs))}")

    return result


# ---------------------------------------------------------------------------
# Layer 3 — LLM gap-filling
# ---------------------------------------------------------------------------

_LLM_SYSTEM = (
    "You are a Linux infrastructure dependency analyst. "
    "Given a list of running services on a RHEL-family server and a set of "
    "vulnerable OS packages with CVEs, determine for each service whether it "
    "likely depends on the vulnerable package. "
    "Respond with a JSON array — one object per service — with these fields:\n"
    "  service      : the service name\n"
    "  dep_risk     : one of SAFE | CHECK_VERSION | VENDOR_BUNDLED | AT_RISK\n"
    "  note         : one sentence explaining the dependency (or lack of one)\n"
    "Rules:\n"
    "- SAFE: the service does not link to or use the package at runtime.\n"
    "- CHECK_VERSION: the service uses the system package; patch is probably safe but operator should verify.\n"
    "- VENDOR_BUNDLED: the service ships its own copy; OS patch won't affect it.\n"
    "- AT_RISK: the service has a known version pin that the patch may violate.\n"
    "Respond with JSON only. No prose, no markdown fences."
)


def _llm_classify_gaps(
    uncovered_svcs: list[str],
    findings: list[dict],
) -> dict[str, dict]:
    """Ask the LLM to classify services not covered by catalogue or RPM graph.

    Returns {svc_name: {dep_risk, note, layer:'llm'}}.
    Skips LLM call when there are no uncovered services or no findings.
    """
    if not uncovered_svcs or not findings:
        return {}

    # Build a compact vulnerability summary (avoid token bloat)
    vuln_summary = [
        {"pkg": f.get("package", ""), "sev": f.get("severity", ""),
         "cve": f.get("cve", ""), "fixed": f.get("fixed", "")}
        for f in findings[:30]  # cap to avoid huge prompts
    ]
    prompt = (
        f"Running services not yet classified:\n{json.dumps(uncovered_svcs, indent=2)}\n\n"
        f"Vulnerable packages (from Trivy scan):\n{json.dumps(vuln_summary, indent=2)}\n\n"
        "Classify each service for each vulnerable package group. "
        "If a service has no dependency on any listed package, return dep_risk=SAFE."
    )

    try:
        raw = generate(_LLM_SYSTEM, prompt)
        # Strip any accidental markdown fences
        raw = re.sub(r'```(?:json)?|```', '', raw).strip()
        items = json.loads(raw)
        result: dict[str, dict] = {}
        for item in items:
            svc = item.get("service", "")
            if svc:
                result[svc] = {
                    "label":           svc,
                    "version":         "",
                    "install_path":    "",
                    "service_running": svc,
                    "dep_risk_override": item.get("dep_risk", "SAFE"),
                    "dep_note_override": item.get("note", ""),
                    "layer":           "llm",
                }
                icon = RISK_LEVELS.get(item.get("dep_risk", "SAFE"), {}).get("icon", "⬜")
                print(f"  [L3-llm] {svc}: {icon} {item.get('dep_risk','SAFE')}")
        return result
    except Exception as exc:
        print(f"  [L3-llm] LLM gap-fill failed: {exc}")
        return {}


# ---------------------------------------------------------------------------
# Main discovery orchestrator
# ---------------------------------------------------------------------------

def discover_products(
    host: str,
    user: str = None,
    opts: list = None,
    findings: list[dict] = None,
    llm_gap_fill: bool = True,
) -> dict[str, dict]:
    """Run all three layers and return a unified detected-products dict."""
    user    = user or SSH_USER
    opts    = opts if opts is not None else ssh_opts()
    findings = findings or []

    # Get running services once — shared by all layers
    svc_out = _ssh_run(
        host, user, opts,
        "systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null",
        timeout=10,
    )
    running_svcs = {
        line.split()[0].replace(".service", "")
        for line in svc_out.splitlines() if line.strip()
    }
    print(f"  Running services detected: {len(running_svcs)}")

    # Layer 1
    detected = _discover_catalogue(host, user, opts, running_svcs)

    # Layer 2 — RPM graph for OS-managed vulnerable packages
    os_pkgs = [
        f.get("package", "")
        for f in findings
        if f.get("package") and ":" not in f.get("package", "")  # skip Maven
    ]
    unique_os_pkgs = list(dict.fromkeys(os_pkgs))[:40]  # cap SSH calls
    if unique_os_pkgs:
        rpm_hits = _discover_rpm_dependents(host, user, opts, unique_os_pkgs)
        # Merge without overwriting L1 entries
        for k, v in rpm_hits.items():
            if k not in detected:
                detected[k] = v

    # Layer 3 — LLM gap-fill for unclassified running services
    if llm_gap_fill and running_svcs:
        # Services not already covered by L1 or L2
        covered_svcs = set()
        for p in detected.values():
            svc = p.get("service_running", "")
            if svc:
                covered_svcs.add(svc)
        uncovered = [
            s for s in sorted(running_svcs)
            if s not in covered_svcs
            and s not in ("dbus", "systemd-journald", "systemd-logind",
                          "NetworkManager", "crond", "auditd", "sshd",
                          "tuned", "rsyslog", "firewalld")
        ][:20]  # cap LLM prompt size

        if uncovered:
            llm_hits = _llm_classify_gaps(uncovered, findings)
            for k, v in llm_hits.items():
                if k not in detected:
                    detected[k] = v

    return detected


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_findings(findings: list[dict], detected: dict[str, dict]) -> list[dict]:
    """Cross-reference findings with detected products to assign dep_risk per finding."""
    results = []
    for f in findings:
        candidates = _normalize_pkg(f.get("package", ""))
        matched_products: list[str] = []
        matched_constraints: list[dict] = []
        is_bundled = False
        llm_override: dict = {}

        for prod_key, prod_info in detected.items():
            layer = prod_info.get("layer", "catalogue")

            # Layer 1 catalogue match
            if layer == "catalogue" and prod_key in KNOWN_PRODUCTS:
                prod_deps = KNOWN_PRODUCTS[prod_key]["dependencies"]
                for cand in candidates:
                    if cand in prod_deps:
                        dep = prod_deps[cand]
                        matched_products.append(KNOWN_PRODUCTS[prod_key]["label"])
                        matched_constraints.append(dep)
                        if dep.get("type") == "bundled":
                            is_bundled = True
                        break

            # Layer 2 RPM graph match
            elif layer == "rpm-graph":
                pkg = f.get("package", "")
                dep_on = prod_info.get("depends_on", [])
                # Match if any candidate matches a package this RPM depends on
                for cand in candidates:
                    if any(cand == d or cand in d or d in cand for d in dep_on):
                        matched_products.append(prod_info["label"])
                        matched_constraints.append({
                            "constraint": None,
                            "type": "system",
                            "note": (
                                f"{prod_info['label']} is installed and links to "
                                f"{pkg} (discovered via RPM dependency graph). "
                                "Restart the service after patching."
                            ),
                        })
                        break

            # Layer 3 LLM override
            elif layer == "llm":
                svc = prod_info.get("service_running", prod_key)
                risk_override = prod_info.get("dep_risk_override", "SAFE")
                if risk_override != "SAFE":
                    llm_override = {
                        "risk": risk_override,
                        "note": prod_info.get("dep_note_override", ""),
                        "products": [svc],
                    }

        # Determine final risk
        if llm_override and not matched_products:
            risk  = llm_override["risk"]
            note  = llm_override["note"]
            prods = llm_override["products"]
        elif not matched_products:
            risk  = "SAFE"
            note  = "No running product on this host depends on this package. Safe to patch."
            prods = []
        elif is_bundled:
            risk  = "VENDOR_BUNDLED"
            note  = " | ".join(c["note"] for c in matched_constraints)
            prods = matched_products
        else:
            risk  = "CHECK_VERSION"
            cstr  = "; ".join(
                f"{p}: {c['constraint'] or 'any'}"
                for p, c in zip(matched_products, matched_constraints)
            )
            note  = " | ".join(c["note"] for c in matched_constraints)
            if cstr:
                note += f"  [Constraints: {cstr}]"
            prods = matched_products

        results.append({
            **f,
            "dep_risk":     risk,
            "dep_label":    RISK_LEVELS[risk]["label"],
            "dep_products": prods,
            "dep_note":     note,
        })
    return results


# ---------------------------------------------------------------------------
# Orchestrator (called from FastAPI background tasks too)
# ---------------------------------------------------------------------------

def run_dep_check(
    findings: list[dict],
    host: str = None,
    live: bool = False,
    llm_gap_fill: bool = True,
) -> dict:
    """Run all three dependency intelligence layers and return structured result."""
    print(f"Dep-check: {len(findings)} findings | host={host or 'local'} | live={live} | llm_gap_fill={llm_gap_fill}")

    if live and host:
        detected = discover_products(host, findings=findings, llm_gap_fill=llm_gap_fill)
    else:
        detected = {}
        print("  Local mode — skipping SSH discovery. All findings classified SAFE.")

    classified = classify_findings(findings, detected)
    risk_counts = Counter(f["dep_risk"] for f in classified)
    print("  Risk summary: " + ", ".join(
        f"{RISK_LEVELS[r]['icon']} {r}: {n}"
        for r, n in sorted(risk_counts.items(), key=lambda x: RISK_LEVELS[x[0]]["priority"])
    ))

    return {
        "host":       host or "local",
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "layers_used": (
            ["catalogue", "rpm-graph", "llm"] if live else []
        ),
        "products":   [{"key": k, **v} for k, v in detected.items()],
        "risk_summary": {r: n for r, n in risk_counts.items()},
        "findings_classified": classified,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    dry          = "--dry"          in args
    live         = "--live"         in args
    no_llm       = "--no-llm"       in args
    args = [a for a in args if a not in ("--dry", "--live", "--no-llm")]

    ait_id: str | None = None
    for i, a in enumerate(args):
        if a == "--ait-id" and i + 1 < len(args):
            ait_id = args[i + 1]
            args   = args[:i] + args[i + 2:]
            break

    report_path = next((a for a in args if not a.startswith("--")), None)

    if not report_path and not live:
        print("Usage:")
        print("  python dep_agent.py report.json [--ait-id AIT-001] [--dry] [--no-llm]")
        print("  python dep_agent.py --live [--ait-id AIT-001] [--no-llm]")
        print()
        print("  --dry      Print discovery results, skip DB write")
        print("  --no-llm   Skip Layer 3 LLM gap-filling")
        sys.exit(1)

    if live:
        import tempfile
        local_scan = os.path.join(tempfile.gettempdir(), "dep_agent_scan.json")
        print(f"Pulling Trivy scan from {TARGET_HOST} ...")
        try:
            subprocess.run(
                ["scp"] + ssh_opts() +
                [f"{SSH_USER}@{TARGET_HOST}:/tmp/trivy_scan.json", local_scan],
                check=True, timeout=30,
            )
            findings = parse_trivy(local_scan)
        except Exception as exc:
            print(f"  Could not pull scan: {exc}")
            findings = []
        host = TARGET_HOST
    else:
        findings = parse_trivy(report_path)
        host     = None

    if not findings:
        print("No findings to classify.")
        return

    result = run_dep_check(
        findings,
        host=host,
        live=live,
        llm_gap_fill=not no_llm,
    )

    if dry:
        print("\n[DRY RUN] Dep-check result:")
        printable = {k: v for k, v in result.items() if k != "findings_classified"}
        print(json.dumps(printable, indent=2, default=str))
        print(f"\nfindings_classified: {len(result['findings_classified'])} items")
        at_risk = [f for f in result["findings_classified"] if f["dep_risk"] != "SAFE"]
        for f in at_risk[:15]:
            icon = RISK_LEVELS[f["dep_risk"]]["icon"]
            print(f"  {icon} {f['cve']} | {f['package']} | {f['dep_label']}")
        return

    if ait_id:
        _store_to_db(result, ait_id)
    else:
        at_risk = [f for f in result["findings_classified"] if f["dep_risk"] != "SAFE"]
        if at_risk:
            print(f"\nFindings requiring attention ({len(at_risk)}):")
            for f in at_risk:
                icon = RISK_LEVELS[f["dep_risk"]]["icon"]
                print(f"  {icon} {f['cve']} | {f['package']} | {f['dep_label']}")
                print(f"     {f['dep_note'][:120]}")


def _store_to_db(result: dict, ait_id: str) -> None:
    try:
        os.environ.setdefault("DATABASE_URL",
                              "postgresql://postgres:postgres@localhost:5432/vulndb")
        from app.database import SessionLocal
        from app import crud, models

        db = SessionLocal()
        try:
            crud.store_dep_report(db, ait_id, result)
            updated = 0
            for f in result["findings_classified"]:
                dep_info = json.dumps({
                    "risk":     f.get("dep_risk", "UNKNOWN"),
                    "label":    f.get("dep_label", ""),
                    "products": f.get("dep_products", []),
                    "note":     f.get("dep_note", ""),
                })
                rows = (
                    db.query(models.Finding)
                    .filter_by(ait_id=ait_id, cve_id=f.get("cve", ""),
                               package=f.get("package", ""))
                    .all()
                )
                for row in rows:
                    crud.update_finding(db, row.id, dep_note=dep_info)
                    updated += 1
            print(f"  Stored dep notes for {updated} finding(s) (AIT {ait_id}).")
        finally:
            db.close()
    except Exception as exc:
        print(f"  [warn] DB store failed: {exc}")


if __name__ == "__main__":
    main()
