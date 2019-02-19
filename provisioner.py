#!/usr/bin/env pythion3

import os
import sys
import json
import requests
import datetime
import uuid

from copy import deepcopy
from http.cookies import SimpleCookie
from requests.cookies import cookiejar_from_dict
from requests import Session
from requests.auth import HTTPBasicAuth

from colorama import Fore, Back, Style

# CONSTANTS

SBS_HOST = os.environ.get("SBS_HOST", "https://sbs.exp.scz.lab.surf.nl")
PUBLISHER_PORT = os.environ.get("PUBLISHER_PORT", "5556")

BASE_DN = os.environ.get("BASE_DN", "ou=sbs,dc=example,dc=org")

LDAP_HOST = os.environ.get("LDAP_HOST", "ldap.exp.scz.lab.surf.nl")
#LDAP_USERNAME = os.environ.get("LDAP_USERNAME", f"cn=admin,{BASE_DN}")
LDAP_USERNAME = os.environ.get("LDAP_USERNAME", "cn=admin")
LDAP_PASSWORD = os.environ.get("LDAP_PASSWORD", None)

API_USER = os.environ.get("API_USER", "sysadmin")
API_PASS = os.environ.get("API_PASS", None)

def log(s):
	print(s)

def timestamp():
	return datetime.datetime.now().strftime("%d.%b %Y %H:%M:%S")

def log_error(s):
	log(Fore.RED+Style.BRIGHT+'['+timestamp()+']: '+Style.NORMAL+s+Fore.RESET)

def log_warning(s):
	log(Fore.YELLOW+s+Fore.RESET)

def log_info(s):
	log(Fore.GREEN+s+Fore.RESET)

def log_debug(s):
	log(Fore.MAGENTA+s+Fore.RESET)

def log_json(data, title=None):
	if title:
		log_info(title)
	log_info(json.dumps(data, indent=4, sort_keys=True))

def panic(s):
	log_error(s)
	sys.exit(1)

def get_json(string, title=None):
	data = json.loads(string)
	log_json(data, title)
	return data

def put_json(data, title=None):
	log_json(data, title)
	return json.dumps(data)

# 0MQ - part

import zmq

try:
	context = zmq.Context()
	publisher = context.socket(zmq.PUB)
	publisher.bind("tcp://*:%s" % PUBLISHER_PORT)
except:
	panic("Publisher cannot be started !")

notifications = None

def push_notification(topic, id):
	global notifications

	if not notifications:
		notifications = {}
		
	if topic not in notifications:
		notifications[topic] = []

	if id not in notifications[topic]:
		notifications[topic].append(id)

def flush_notifications():
	global notifications
	
	if not notifications:
		return

	for topic in notifications:
		for id in notifications[topic]:
			log_debug(f"Notifying: {topic}:{id}")
			publisher.send(f"{topic}:{id}".encode())

	notifications = None

# LDAP - part

import ldap
import ldap.modlist as modlist

ldap_session = None

try:
	ldap_session = ldap.initialize(f"ldaps://{LDAP_HOST}")
	ldap_session.bind_s(LDAP_USERNAME, LDAP_PASSWORD)
except:
	ldap_session.unbind_s()
	panic("LDAP connection failed !")

def log_ldap_result(r):
	log_debug(f"[LDAP SEARCH RESULT]")

	if not r:
		log_debug("<empty>")
	elif len(r) == 0:
		log_debug("[]")
	else:
		for i in r:
			log_debug(f"\tDN:\t{i[0]}\n\tDATA:\t{i[1]}")

def ldap_organisations():
	l = ldap_session.search_s(BASE_DN, ldap.SCOPE_ONELEVEL, f"(&(objectclass=organizationalUnit)(ou=*))")
	log_ldap_result(l)
	return l

def ldap_collobarations(org):
	l = ldap_session.search_s(f"ou={org},{BASE_DN}", ldap.SCOPE_ONELEVEL, f"(&(objectclass=organizationalUnit)(ou=*))")
	log_ldap_result(l)
	return l

def ldap_people(base):
	l = ldap_session.search_s(f"ou=people,{base}", ldap.SCOPE_ONELEVEL, f"(&(objectclass=organizationalPerson)(cn=*))")
	log_ldap_result(l)
	return l
 
def ldap_ou(topic, base, ou, name, description):

	log_debug(f"[LDAP_OU]\n\tBase: {base}\n\tOU: {ou}\n\tNAME: {name}\n\tDESCRIPTION: {description}")

	result = ldap_session.search_s(base, ldap.SCOPE_ONELEVEL, f"(&(objectclass=organizationalUnit)(ou={ou}))")
	log_ldap_result(result)

	if len(result) == 0:

		attrs = {}
		attrs['objectclass'] = [ b'top', b'organizationalUnit', b'extensibleObject']
		attrs['name'] = name.encode()
		attrs['description'] = description.encode()

		ldif = modlist.addModlist(attrs)

		try:
			ldap_session.add_s(f"ou={ou},{base}" , ldif)
			ldap_session.add_s(f"ou=people,ou={ou},{base}" , ldif)
			ldap_session.add_s(f"ou=groups,ou={ou},{base}" , ldif)
		except Exception as e:
			panic(f"Error during LDAP ADD, Error: {str(e)}")

		push_notification(topic, ou)

def ldap_member(topic, id, base, role, uid, name):

	log_debug(f"[LDAP_MEMBER]\n\tBase: {base}\n\tROLE: {role}\n\tUID: {uid}\n\tNAME: {name}")

	result = ldap_session.search_s(f"ou=people,{base}", ldap.SCOPE_ONELEVEL, f"(&(objectclass=organizationalPerson)(cn={uid}))")
	log_ldap_result(result)

	if len(result) == 0:
		
		attrs = {}
		attrs['objectclass'] = [ b'top', b'organizationalPerson']
		attrs['sn'] = name.encode()

		ldif = modlist.addModlist(attrs)

		try:
			ldap_session.add_s(f"cn={uid},ou=people,{base}", ldif)
		except Exception as e:
			panic(f"Error during LDAP ADD, Error: {str(e)}")

		push_notification(topic, id)

	result = ldap_session.search_s(f"ou=groups,{base}", ldap.SCOPE_ONELEVEL, f"(cn={role})")
	log_ldap_result(result)

	if len(result) > 0:
		log_debug("MEMBER DATA: " + str(result[0][1]))
		if 'member' in result[0][1]:
			log_debug("MEMBERS UIDs: " + str(result[0][1]['member']))

	if len(result) == 0 or 'member' not in result[0][1]:

		attrs = {}
		attrs['objectclass'] = [ b'groupOfNames']
		attrs['member'] = [ f"cn={uid},ou=people,{base}".encode() ]

		ldif = modlist.addModlist(attrs)
		try:
			ldap_session.add_s(f"cn={role},ou=groups,{base}", ldif)
		except Exception as e:
			panic(f"Error during LDAP ADD, Error: {str(e)}")

		push_notification(topic, id)

	elif f"cn={uid},ou=people,{base}".encode() not in result[0][1]['member']:

		attrs = deepcopy(result[0][1])
		attrs['member'].append(f"cn={uid},ou=people,{base}".encode())

		log_debug("OLD: "+str(result[0][1]))
		log_debug("NEW: "+str(attrs))

		ldif = modlist.modifyModlist(result[0][1], attrs)
		try:
			ldap_session.modify_s(f"cn={role},ou=groups,{base}", ldif)
		except Exception as e:
			panic(f"Error during LDAP ADD, Error: {str(e)}")

		push_notification(topic, id)
	
def ldap_delete(topic, id, dn):
	log_debug(f"LDAP DELETE {topic}:{id}, DN: {dn}")

	push_notification(topic, id)
	
	try:
		ldap_session.delete_s(dn)
	except Exception as e:
		panic(f"Error during LDAP delete DN: {dn}, Error: {str(e)}")

# handle error however you like
# API - part

session = None

def api(url, method='GET', headers=None, data=None):
	global session

	if session:
		log_debug(f"AUTHENTICATED REQUEST: {url}")
		r = session.request(method, url=url, headers=headers, data=data)
	else:
		log_debug(f"PUBLIC REQUEST: {url}")
		r = requests.request(method, url=url, headers=headers, auth=HTTPBasicAuth(API_USER, API_PASS), data=data)

	log_debug('\n'.join(f'{k}: {v}' for k, v in r.headers.items()))

	if 'Set-Cookie' in r.headers:
		session = Session()

		my_cookie = SimpleCookie()
		my_cookie.load(r.headers['Set-Cookie'])

		cookies = {key: morsel.value for key, morsel in my_cookie.items()}
		log_json(cookies)
		session.cookies = cookiejar_from_dict(cookies)

	if r.status_code == 200:
		try:
			return get_json(r.text)
		except:
			log_info(r.text)
			return r.text
	else:
		log_error(f"API: {url} returns: {r.status_code}")

	return None

health = api(SBS_HOST+"/health")
if not health or health['status'] != "UP":
	panic("Server is not UP !")
	
api(SBS_HOST+"/api/users/me", headers ={"Mellon_Cmuid": "urn:john"})

organisations = api(SBS_HOST+"/api/organisations")
for o in organisations:
	log_debug(f"org: [{o['id']}]: {o['name']}, description: {o['description']}, tenant: {o['tenant_identifier']} ")

	ldap_ou('O', BASE_DN, o['name'], o['tenant_identifier'], o['description'])

	for m in o['organisation_memberships']:		
		log_debug(f"- member [{m['role']}]: {m['user']['uid']}")

		ldap_member('O', o['name'], f"ou={o['name']},{BASE_DN}", m['role'], m['user']['uid'], m['user']['name'])


co_users = {}

collaborations = api(SBS_HOST+"/api/collaborations")
for c in collaborations:
	log_debug(f"CO [{c['id']}]: {c['name']}, description: {c['description']}")

	ldap_ou('CO', f"ou={c['organisation']['name']},{BASE_DN}", c['name'], f"{c['organisation']['name']} - {c['name']}", c['description'])

	co_users[c['name']] = {}

	try:
		for u in c['invitations']:
			co_users[c['name']][u["user_id"]] = { 'name': u['invitee_email'], 'uid' : str(uuid.uuid4()), 'role': 'invited' }
	except Exception as e:
		log_error(str(e))

	try:
		for u in c['join_requests']:
			co_users[c['name']][u["user_id"]] = u["user"] 
	except Exception as e:
		log_error(str(e))

	log_json(co_users[c['name']])

	try:
		for m in c['collaboration_memberships']:
			log_debug(f"- member [{m['role']}]")

			ldap_member('CO', c['name'], 
				f"ou={c['name']},ou={c['organisation']['name']},{BASE_DN}", 
				m['role'], 
				co_users[c['name']][m['user_id']]['uid'], 
				co_users[c['name']][m['user_id']]['name']
			)

			try:
				for p in m['user_service_profiles']:
					log_debug(f"-- profile: {p['id']}]")
			except Exception as e:
				log_error(str(e))

	except Exception as e:
		log_error(str(e))

	try:
		for s in c['services']:
			log_debug(f"- service [{s['name']}]")
	except:
		log_debug(f"CO [{c['id']}]: {c['name']} contains no services...")


# Cleanup redundant objects...

for org in ldap_organisations():

	if org[0].startswith("ou=people,") or org[0].startswith("ou=groups,"):
		continue

	log_debug(f"CHECK O: {org[0]}...")
	org_validated = False

	for o in organisations:
		if org[0] == f"ou={o['name']},{BASE_DN}":

			org_validated = True

			for co in ldap_collobarations(o['name']):

				if co[0].startswith("ou=people,") or co[0].startswith("ou=groups,"):
					continue

				log_debug(f"CHECK CO: {co[0]}...")
				co_validated = False
			
				for c in collaborations:
					if co[0] == f"ou={c['name']},ou={o['name']},{BASE_DN}":
						co_validated = True
						break

				if co_validated:
					log_debug(f"CHECK CO: {co[0]} VALIDATED !")

					for m in ldap_people(f"ou={c['name']},ou={o['name']},{BASE_DN}"):
						cn = m[1]['cn'][0].decode()

						log_debug(f"CHECK CO PERSON: {cn}...")
						person_validated = False

						for u in co_users[c['name']]:
							if co_users[c['name']][u]['uid'] == cn:
								person_validated = True
								break

						if person_validated:
							log_debug(f"CHECK CO PERSON: {cn} VALIDATED !")
						else:
							ldap_delete("P", cn, m[0])
						
				else:
					# CO not found, remove it
					ldap_delete("CO", co['name'], co[0])

	if org_validated:
		log_debug(f"CHECK O: {org[0]} VALIDATED !")

		for m in ldap_people(f"ou={o['name']},{BASE_DN}"):
			cn = m[1]['cn'][0].decode()

			log_debug(f"CHECK ORG PERSON: {cn}...")
			person_validated = False

			for om in o['organisation_memberships']:
				if om['user']['uid'] == cn:
					person_validated = True
					break

			if person_validated:
				log_debug(f"CHECK ORG PERSON: {cn} VALIDATED !")
			else:
				ldap_delete("P", cn, m[0])
	else:
		# Org not found, remove it !
		ldap_delete("O", o['name'], org[0])

api(SBS_HOST+"/api/services/search")

ldap_session.unbind_s()

flush_notifications()

log_info("Done !")

exit(0)
