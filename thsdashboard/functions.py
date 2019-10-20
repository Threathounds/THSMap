import xmltodict
import json
import os
import hashlib
import re


# redundant, remove later
def token_check(token):
	tokenhash = open('/root/token.sha256').read().strip()
	if tokenhash == hashlib.sha256(token.encode('utf-8')).hexdigest():
		return True
	return False


def labelToMargin(label):
	labels = {
		'Vulnerable':'10px',
		'Critical':'22px',
		'Warning':'28px',
		'Checked':'28px'
	}

	if label in labels:
		return labels[label]


def labelToColor(label):
	labels = {
		'Vulnerable':'red',
		'Critical':'black',
		'Warning':'orange',
		'Checked':'blue'
	}

	if label in labels:
		return labels[label]


def fromOSTypeToFontAwesome(ostype):
	icons = {
		'windows':'fab fa-windows',
		'solaris':'fab fa-linux',	# there isn't a better icon on fontawesome :(
		'unix':'fab fa-linux',		# same here...
		'linux':'fab fa-linux',
	}

	if ostype.lower() in icons:
		return str(icons[ostype.lower()])
	else:
		return 'fas fa-question'


# function to parse XML file
def parse_xml(xmlfile):
	try:
		# get XML data
		xml_data = xmltodict.parse(open('xml/' + scanfile, 'r').read())
	except:
		# no XML file? return no data
		return {'ports_open': 0, 'ports_closed': 0, 'ports_filtered': 0}

	# convert XML to raw JSON
	raw_json = json.dumps(xml_data['nmaprun'], indent=4)
	# convert raw JSON to Python list
	return json.loads(raw_json)


def nmap_ports_stats(scanfile):
	parsed_json = parse_xml(scanfile)
	debug = {}  # for showing debug output in the dashboard

	# got XML file, but no systems? return no data
	if 'host' not in parsed_json:
		return {'ports_open':0,'ports_closed':0,'ports_filtered':0}

	total_ports, ports_open, ports_closed, ports_filtered = 0, 0, 0, 0
	lastaddress = ''  # ?
	for hosts in parsed_json['host']:
		if type(hosts) is dict:  # got multiple targets, not just one
			individual_host = hosts
		else:  # got one target only
			individual_host = parsed_json['host']

		lastportid = 0

		if '@addr' in individual_host['address']:
			address = individual_host['address']['@addr']
		elif type(individual_host['address']) is list:
			for ai in individual_host['address']:  # there can be 3 types of addresses: MAC, IPv4 and IPv6
				if ai['@addrtype'] == 'ipv4':  # just get the IPv4 address
					address = ai['@addr'] 

		addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

		if lastaddress == address:
			continue
		lastaddress = address

		if 'ports' in individual_host and 'port' in individual_host['ports']:
			for port in individual_host['ports']['port']:
				if type(port) is dict:
					p = port
				else:
					p = individual_host['ports']['port']

				if lastportid == p['@portid']:
					continue
				else:
					lastportid = p['@portid']

				if address not in debug:
					debug[address] = {'portcount':{'ports_closed':{},'ports_open':{},'ports_filtered':{}}}
				debug[address][p['@portid']] = p['state']

				if p['state']['@state'] == 'closed':
					ports_closed = (ports_closed + 1)
					debug[address]['portcount']['ports_closed'][total_ports] = ports_closed
				elif p['state']['@state'] == 'open':
					ports_open = (ports_open + 1)
					debug[address]['portcount']['ports_open'][total_ports] = ports_open
				elif p['state']['@state'] == 'filtered':
					ports_filtered = (ports_filtered + 1)
					debug[address]['portcount']['ports_filtered'][total_ports] = ports_filtered
				total_ports = (total_ports + 1)
				# print(total_ports)

	return {'ports_open':ports_open,'ports_closed':ports_closed,'ports_filtered':ports_filtered, 'debug':json.dumps(debug)}


def get_cve(scanmd5):
	cvehost = {}
	cvefiles = os.listdir('notes')
	for cf in cvefiles:
		m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32})\.cve$', cf)
		if m is not None:
			if m.group(1) not in cvehost:
				cvehost[m.group(1)] = {}

			if m.group(2) not in cvehost[m.group(1)]:
				cvehost[m.group(1)][m.group(2)] = open('notes/'+cf, 'r').read()

			#cvehost[m.group(1)][m.group(2)][m.group(3)] = open('notes/'+cf, 'r').read()

	return cvehost


def get_ports_details(scanfile):
	faddress = ""
	oo = xmltodict.parse(open('xml/'+scanfile, 'r').read())
	out2 = json.dumps(xml_data['nmaprun'], indent=4)
	o = json.loads(out2)

	r = {'file':scanfile, 'hosts': {}}
	scanmd5 = hashlib.md5(str(scanfile).encode('utf-8')).hexdigest()

	# collect all labels in labelhost dict
	labelhost = {}
	labelfiles = os.listdir('notes')
	for lf in labelfiles:
		m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32})\.host\.label$', lf)
		if m is not None:
			if m.group(1) not in labelhost:
				labelhost[m.group(1)] = {}
			labelhost[m.group(1)][m.group(2)] = open('notes/'+lf, 'r').read()

	# collect all notes in noteshost dict
	noteshost = {}
	notesfiles = os.listdir('notes')
	for nf in notesfiles:
		m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32})\.notes$', nf)
		if m is not None:
			if m.group(1) not in noteshost:
				noteshost[m.group(1)] = {}
			noteshost[m.group(1)][m.group(2)] = open('notes/'+nf, 'r').read()

	# collect all cve in cvehost dict
	cvehost = get_cve(scanmd5)

	for ik in parsed_json['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = parsed_json['host']

		hostname = {}
		if 'hostnames' in individual_host and type(individual_host['hostnames']) is dict:
			# hostname = json.dumps(individual_host['hostnames'])
			if 'hostname' in individual_host['hostnames']:
				# hostname += '<br>'
				if type(individual_host['hostnames']['hostname']) is list:
					for hi in individual_host['hostnames']['hostname']:
						hostname[hi['@type']] = hi['@name']
				else:
					hostname[individual_host['hostnames']['hostname']['@type']] = individual_host['hostnames']['hostname']['@name'];

		if individual_host['status']['@state'] == 'up':
			ports_open,ports_closed,ports_filtered = 0,0,0
			ss,pp,ost = {},{},{}
			lastportid = 0

			if '@addr' in individual_host['address']:
				address = individual_host['address']['@addr']
			elif type(individual_host['address']) is list:
				for ai in individual_host['address']:
					if ai['@addrtype'] == 'ipv4':
						address = ai['@addr']

			if faddress != "" and faddress != address:
				continue

			addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
			#cpe[address] = {}

			labelout = ''
			if scanmd5 in labelhost:
				if addressmd5 in labelhost[scanmd5]:
					labelout = labelhost[scanmd5][addressmd5]

			notesout,notesb64,removenotes = '','',''
			if scanmd5 in noteshost:
				if addressmd5 in noteshost[scanmd5]:
					notesb64 = noteshost[scanmd5][addressmd5]
			#		notesout = '<br><a id="noteshost'+str(hostindex)+'" href="#!" onclick="javascript:openNotes(\''+hashlib.md5(str(address).encode('utf-8')).hexdigest()+'\', \''+notesb64+'\');" class="small"><i class="fas fa-comment"></i> contains notes</a>'
			#		removenotes = '<li><a href="#!" onclick="javascript:removeNotes(\''+addressmd5+'\', \''+str(hostindex)+'\');">Remove notes</a></li>'

			cveout = ''
			#cvecount = 0
			if scanmd5 in cvehost:
				if addressmd5 in cvehost[scanmd5]:
					cveout = json.loads(cvehost[scanmd5][addressmd5])
			#		for cveobj in cvejson:	
			#			cvecount = (cvecount + 1)


			#if faddress == "":
			#	r['hosts'][address] = {'hostname':hostname, 'label':labelout, 'notes':notesb64}
			#else:
			r['hosts'][address] = {'ports':[], 'hostname':hostname, 'label':labelout, 'notes':notesb64, 'CVE':cveout}

			if 'ports' in individual_host and 'port' in individual_host['ports']:
				for port in individual_host['ports']['port']:
					if type(port) is dict:
						p = port
					else:
						p = individual_host['ports']['port']

					if lastportid == p['@portid']:
						continue
					else:
						lastportid = p['@portid']

					v,z,e='','',''
					pp[p['@portid']] = p['@portid']

					servicename = ''
					if 'service' in p:
						ss[p['service']['@name']] = p['service']['@name']

						if '@version' in p['service']:
							v = p['service']['@version']

						if '@product' in p['service']:
							z = p['service']['@product']

						if '@extrainfo' in p['service']:
							e = p['service']['@extrainfo']

						servicename = p['service']['@name']

					#if faddress != "":
					r['hosts'][address]['ports'].append({
						'port': p['@portid'],
						'name': servicename,
						'state': p['state']['@state'],
						'protocol': p['@protocol'],
						'reason': p['state']['@reason'],
						'product': z,
						'version': v,
						'extrainfo': e
					})
	return r
