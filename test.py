from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime as dt
import xml.etree.ElementTree as et
import requests as rq
import csv
import pandas as pd
import matplotlib.pyplot as plt
import base64
from yattag import Doc
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import smtplib,ssl
import os
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

rq.packages.urllib3.disable_warnings(InsecureRequestWarning)
head = {'User-Agent': 'curl/7.64.1', 'X-Requested-With': 'Curl Sample', 'Authorization': 'Basic '}
dc = {}
score = {}

def asset_count(tag):
	print("[*] Fetching Assets Count .....")
	aw = []
	al = []
	url = "https://qualysapi.qualys.com/qps/rest/2.0/search/am/hostasset/"
	data="""
<ServiceRequest>
<preferences>
<limitResults>999</limitResults>
</preferences>
<filters>
<Criteria field="tagName" operator="EQUALS">{}</Criteria>
</filters>
</ServiceRequest>""".format(tag)
	res = rq.post(url, data=data, headers=head, verify=False)
	root = et.XML(res.content.decode('utf-8'))
	for i in root.find('data'):
		if 'Windows' in i.find('os').text:
			aw.append(i[0].text)
		else:
			al.append(i[0].text)
	if root.find('hasMoreRecords').text == 'true':
		val = root.find('lastId').text
		d1 = """
<ServiceRequest>
<preferences>
<limitResults>999</limitResults>
</preferences>
<filters>
<Criteria field="id" operator="GREATER">{}</Criteria>
<Criteria field="tagName" operator="EQUALS">{}</Criteria>
</filters>
</ServiceRequest>""".format(val, tag)
		res = rq.post(url, data=d1, headers=head, verify=False)
		root = et.XML(res.content.decode('utf-8'))
		for i in root.find('data'):
			if 'Windows' in i.find('os').text:
				aw.append(i[0].text)
			else:
				al.append(i[0].text)
	return len(aw), len(al)

def upload(file1):
	print("[*] Uploading Files to Gdrive .....")
	gauth = GoogleAuth()
	scope = ["https://www.googleapis.com/auth/drive"]
	gauth.credentials = ServiceAccountCredentials.from_json_keyfile_name('client_secrets.json', scope)
	drive = GoogleDrive(gauth)
	gfile = drive.CreateFile({'parents': [{'id': parentid}]})
	gfile.SetContentFile(file1)
	gfile.Upload()

def get_data():
	print("[*] Downloading the report ......")
	res = rq.post("https://qualysapi.qualys.com/api/2.0/fo/report/", data={"action": "launch", "template_id": id, "report_title": title, "output_format": "csv"}, headers=head, verify=False)
	rdata = et.fromstring(res.content)
	report_id = rdata[0][2][0][1].text
	time.sleep(60)
	while True:
		time.sleep(20)
		url = "https://qualysapi.qualys.com/api/2.0/fo/report/?action=fetch&id="+str(report_id)
		res = rq.get(url, headers=head, verify=False)
		if ("csv" in res.headers["Content-Type"]):
			file = open("name.csv", "wb")
			file.write(res.content)
			file.close()
			break
		else:
			continue
	return

def sev(data):
	nf = data[data['Vuln Status'] != 'Fixed']
	total = len(data['IP'])
	active = len(nf['First Detected'])
	if data['Vuln Status'].str.contains('Fixed').any() == True:
		rem = data['Vuln Status'].value_counts()['Fixed']
	else:
		rem = 0
	if nf.Severity.astype(str).str.contains('5').any() == True:
		a5 = nf.Severity.value_counts()[5]
	else:
		a5 = 0
	if nf.Severity.astype(str).str.contains('4').any() == True:
		a4 = nf.Severity.value_counts()[4]
	else:
		a4 = 0
	if nf.Severity.astype(str).str.contains('3').any() == True:
		a3 = nf.Severity.value_counts()[3]
	else:
		a3 = 0
	if nf.Severity.astype(str).str.contains('2').any() == True:
		a2 = nf.Severity.value_counts()[2]
	else:
		a2 = 0
	if nf.Severity.astype(str).str.contains('1').any() == True:
		a1 = nf.Severity.value_counts()[1]
	else:
		a1 = 0
	return total, active, rem, a1, a2, a3, a4, a5

def vdata():
	global score
	df = pd.read_csv("filename.csv", skiprows=4)
	name = "filename_"+dt.today().strftime("%d_%m_%Y")+".xlsx"
	df.to_excel(name, index=False)
	upload(name)
	lin = df[~df['OS'].str.contains('windows', case=False, regex=True)]
	total, active, r, b1, b2, b3, b4, b5 = sev(lin)
	score['linux'] = [b5, b4, b3, b2, b1]
	dc['linux'] = [total, active, r]
	win = df[df['OS'].str.contains('windows', case=False, regex=True)]
	total, active, r, b1, b2, b3, b4, b5 = sev(win)
	score['win'] = [b5, b4, b3, b2, b1]
	dc['win'] = [total, active, r]
	return
	
def plotbase64string(key):
	plt.clf()
	x = ['5','4','3','2','1']
	y = score[key]
	col = ['darkred','red', 'orange', 'gold', 'blue']
	plt.bar(x, y, color=col)
	plt.xlabel("Severity")
	plt.ylabel("Vulnerabilities")
	for i,j in enumerate(y):
		plt.text(i,j, str(j))
	if key == 'win':
		plt.title("Vulnerabilities by Severity - Windows OS")
	if key == 'linux':
		plt.title("Vulnerabilities by Severity - Linux OS")
	plt.savefig(key+".png", format='png')

def gather():
	global dc
	get_data()
	vdata()
	for i in dc:
		plotbase64string(i)

def tab_head():
	heads = ['Device Type', 'Current Asset Count','Total Vulnerabilities','Active Vulnerabilities (Current Scan)', 'Vulnerabilities Remediated','% of Remediation']
	doc, tag, text = Doc().tagtext()
	with tag('thead'):
		with tag('tr'):
			for i in heads:
				doc.line('th', i, style='word-wrap: break-word')
	return doc.getvalue()

def get_row(plat, tov, aset):
	doc, tag, text = Doc().tagtext()
	with tag('tr'):
		doc.line('td',plat, style='aligh: center; vertical-align: middle')
		doc.line('td', str(aset), style='text-align: center; vertical-align: middle')
		doc.line('td', str(dc[tov][0]), style='text-align: center; vertical-align: middle')
		doc.line('td', str(dc[tov][1]), style='text-align: center; vertical-align: middle')
		doc.line('td', str(dc[tov][2]), style='text-align: center; vertical-align: middle')
		if dc[tov][2] == 0:
			pc = "0%"
		else:
			pc = str(round(int(dc[tov][2])/int(dc[tov][0])*100))+str("%")
		doc.line('td', str(pc), style='text-align: center; vertical-align: middle')
	return doc.getvalue()

def get_table():
	doc, tag, text = Doc().tagtext()
	with tag('table', klass='all-pr', border='1px', style='table-layout: Fixed;'):
		doc.asis(tab_head())
		with tag('tbody'):
			doc.asis(get_row('Windows OS', 'win', aw))
			doc.asis(get_row('Linux OS', 'linux', al))
	return doc.getvalue()

def compose_email():
	introduction = str("Hello All, this is the VM Report")
	conclusion = str("Kind Regards")
	msgRoot = MIMEMultipart('related')
	msgRoot.preamble = 'This is a multi-part message in MIME format.'
	msgAlternative = MIMEMultipart('alternative')
	msgRoot.attach(msgAlternative)
	doc, tag, text = Doc().tagtext()
	doc1, tag1, text1 = Doc().tagtext()
	with tag('div'):
		doc.asis(introduction)
		with tag('H3'):
			with tag('u'):
				text("Vulnerability Status")
		doc.asis(get_table())
		with tag('div'):
			with tag('p'):
				with tag('H3'):
					with tag('u'):
						text("Vulnerabilities by Severity")
			doc.stag('img', src='cid:image1')
			doc.stag('img', src='cid:image2')
	doc.asis(conclusion)
	part1 = doc.getvalue()
	msgText = MIMEText(str(part1), 'html')
	msgAlternative.attach(msgText)
	with open("win.png", 'rb') as file:
		msgImage1 = MIMEImage(file.read())
	with open("linux.png", 'rb') as file:
		msgImage2 = MIMEImage(file.read())
	msgImage1.add_header('Content-ID','<image1>')
	msgImage2.add_header('Content-ID','<image2>')
	msgRoot.attach(msgImage1)
	msgRoot.attach(msgImage2)
	return msgRoot

def mail_send(messageRoot):
	sender = "Qualys Bot <qualys@qualys.com"
	recipients = [hello@xyz.com]
	cc = ['hello@xyz.com']
    ###########################
	message = MIMEMultipart("alternative")	
	message['From'] = sender
	message['To'] = ",".join(recipients)
	message['cc'] = ",".join(cc)
	message['Subject'] = "Vulnerability Dashboard"
	message.attach(messageRoot)
	username = 'username'
	password = 'password'
	context = ssl.create_default_context()
	server=smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context)
	server.login(username, password)
	toaddrs = recipients #+ cc
	server.sendmail(sender, toaddrs, message.as_string())
	print(message['Subject']," to: ",message['To']) #, " cc: ", message['cc'])

a,b = asset_count("tag_name")
c,d = asset_count("tag_name")
aw = a+c
al = b+d
gather()
msg = compose_email()
mail_send(msg)
