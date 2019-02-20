# SBS-LDAP-Provisioner
SBS LDAP provisioner

# Install

Please make sure to install both **docker** and **docker-compose**

Copy the file **env.sample** to **.env** and adjust the configuration items according to your situation.

Configurations items:

Config | Meaning | Example
--- | --- | ---
LOG_LEVEL | The desired logging level, choose between: debug, info, warning or error | debug
SBS_HOST | The URL on which your SBS is hosted | https://wbs.example.org
PUBLISHER_PORT | The port for the notification queue | 5556
BASE_DN | the BASE DN of the LDAP | ou=sbs,dc=example,dc=org
LDAP_HOST | The host on which your LDAP can be accessed via ldaps protocol | ldap.example.org
LDAP_USERNAME | the LDAP username that can write the LDAP | cn=admin,dc=example,dc=org
LDAP_PASSWORD | The LDAP password for that LDAP user | <your LDAP password>
API_USER | The SBS API username that can initiate the SBS API's | sysadmin
API_PASS | THE password associated to that API user | <your API password>

when completed, execute:
```
docker-compose build
```

followed by:
```
docker-compose up -d
```

You can watch for output via:

```
docker-compose logs
```

# Notifications

The Provisioner script notifies on acutal updates via a publish/subscribe mechanism that you can subscribe to.

TODO: Include sample of python notification subscribe script