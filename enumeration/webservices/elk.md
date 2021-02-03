# ELK

## Elasticsearch

### Enum

```text
# Check status:
curl -X GET "ELASTICSEARCH-SERVER:9200/"

# Check Auth enabled:
curl -X GET "ELASTICSEARCH-SERVER:9200/_xpack/security/user"

# Users:
elastic:changeme
kibana_system
logstash_system
beats_system
apm_system
remote_monitoring_user

# Other endpoints
/_cluster/health
/_cat/indices
/_cat/health

# Interesting endpoints (BE CAREFUL)
/_shutdown
/_cluster/nodes/_master/_shutdown
/_cluster/nodes/_shutdown
/_cluster/nodes/_all/_shutdown
```

### With creds

```text
# Using the API key:
curl -H "Authorization: ApiKey <API-KEY>" ELASTICSEARCH-SERVER:9200/

# Get more information about the rights of an user:
curl -X GET "ELASTICSEARCH-SERVER:9200/_security/user/<USERNAME>"

# List all users on the system:
curl -X GET "ELASTICSEARCH-SERVER:9200/_security/user"

# List all roles on the system:
curl -X GET "ELASTICSEARCH-SERVER:9200/_security/role
```

### Internal config files

```text
Elasticsearch configuration: /etc/elasticsearch/elasticsearch.yml
Kibana configuration: /etc/kibana/kibana.yml
Logstash configuration: /etc/logstash/logstash.yml
Filebeat configuration: /etc/filebeat/filebeat.yml
Users file: /etc/elasticsearch/users_roles
```

## Kibana

### Basic

```text
# Port: 5601
# Config file && users: /etc/kibana/kibana.yml
# Try also with use kibana_system
# Version < 6.6.0 = RCE (https://github.com/LandGrey/CVE-2019-7609/)
```

## Logstash

### Basic

```text
# Pipelines config: /etc/logstash/pipelines.yml
# Check pipelines with this property: "config.reload.automatic: true"
# If file wildcard is specified:
###################
input {
  exec {
    command => "whoami"
    interval => 120
  }
}

output {
  file {
    path => "/tmp/output.log"
    codec => rubydebug
  }
}
####################
```

