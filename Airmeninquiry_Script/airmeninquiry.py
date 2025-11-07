####	Import modules
import re
import os
import json
import traceback
import glob
import warnings
import random
import sys
import time
import logging
import jsonschema
import boto3
import uuid
import datetime
from logging.config import dictConfig
warnings.filterwarnings("ignore")


from bs4 import BeautifulSoup
import requests


####	regex match
def regex_match(regex,content):
	if content==None:
		return ''
	match = re.search(regex,content,flags=re.I)
	if match:
		return match.group(1)
	return ''


#####	unwanted spaces replace and decode values
def replace(data):
	data=BeautifulSoup(data,'html.parser')
	data = data.get_text()
	data=re.sub('\s\s+',' ',data)
	data=re.sub('^\s+|\s+$','',data)
	return data


def make_directory(folder_paths):
	for folder_path in folder_paths:
		if not os.path.exists(folder_path):
			os.makedirs(folder_path)


####	content fetch from url
def content_fetch(url='',method='get',headers={},post_param={}):
	logging.info('Inside Content Fetch Function')
	logging.debug(f'URL:{url}, Method:{method}, Header:{headers}, Parameter:{post_param}')
	retry=0
	while retry<3:
		try:
			if method=='get':
				obj = sess.get(url,headers=headers,proxies=proxy,verify=False)
				# obj = sess.get(url,headers=headers)
			else:
				obj = sess.post(url,data=post_param,headers=headers,proxies=proxy,verify=False)
			logging.debug(f'Response Code : {obj.status_code}')
			if re.search('^2',str(obj.status_code)):
				return obj
			elif re.search('^5',str(obj.status_code)):
				time.sleep(10)
			else:
				return obj
			retry+=1
		except:
			logging.error(traceback.format_exc())
			time.sleep(10)
	return 1


# Define a function to recursively generate an empty JSON object
def generate_empty_json_object(schema):
    if schema["type"] == "object":
        return {k: generate_empty_json_object(v) for k, v in schema.get("properties", {}).items() if k!='Comments'}
    elif schema["type"] == "array":
        return []
    else:
        return ""


def get_search_data(input_data):
	global session_id,output_schema
	logging.info('Inside Search Data Function')

	first_name=re.sub('^\s+|\s+$','',re.sub('\s\s+',' ',input_data['firstName']))
	last_name=re.sub('^\s+|\s+$','',re.sub('\s\s+',' ',input_data['lastName']))
	personBioId=re.sub('^\s+|\s+$','',re.sub('\s\s+',' ',input_data['personBioId']))
	licenseNumber=re.sub('^\s+|\s+$','',re.sub('\s\s+',' ',input_data['licenseNumber']))
	licenseTypeCode=re.sub('^\s+|\s+$','',re.sub('\s\s+',' ',input_data['licenseTypeCode']))
	licenseStatus=re.sub('^\s+|\s+$','',re.sub('\s\s+',' ',input_data['licenseStatus']))

	logging.debug('Before home page ping')
	header=json_config['home_page_headers']
	header['X-Crawlera-Session']='create'
	obj = content_fetch(url=json_config['home_page_url'],method='get',headers=header)
	
	home_page_content=obj.text
	if re.search(json_config['site_maintenance_reg'],home_page_content,flags=re.I):
		logging.error('Airmeninquiry website is un-available, due to under maintenance.')
		return [],-1
	session_id=obj.headers['X-Crawlera-Session']
	logging.debug(f'Crawlera Session ID ::  {session_id}')
	post_param=json_config['search_page']['parameter'].copy()
	post_param['ctl00$content$ctl01$txtbxLastName']=last_name
	post_param['ctl00$content$ctl01$txtbxFirstName']=first_name
	post_param_reg=json_config['search_page']['parameter_regex']
	for post_param_key in post_param_reg.keys():
		post_param[post_param_key]=regex_match(post_param_reg[post_param_key],home_page_content)

	####	Ping search result content
	logging.debug('Before list search')
	time.sleep(random.randint(json_config['min_sleep'],json_config['max_sleep']))
	header=json_config['search_page']['headers']
	header['X-Crawlera-Session']=session_id
	obj = content_fetch(url=json_config['search_page']['url'],method='post',post_param=post_param,headers=header)
	# with open('list_content.html','wb') as fh:
		# fh.write(obj.content)
	list_content=obj.text

	
	detail_post_param=json_config['detail_page']['parameter'].copy()
	detail_post_param['ctl00$content$ctl01$txtbxLastName']=last_name
	detail_post_param['ctl00$content$ctl01$txtbxFirstName']=first_name
	detail_post_param_reg=json_config['detail_page']['parameter_regex']
	for post_param_key in detail_post_param_reg.keys():
		detail_post_param[post_param_key]=regex_match(detail_post_param_reg[post_param_key],list_content)

	list_ids=re.findall(json_config['detail_page']['list_param_reg'],list_content,flags=re.I)
	full_output_data=[]
	count=0
	for list_id in list_ids:
		name=list_id[1]
		list_id=list_id[0]
		detail_post_param['__EVENTTARGET']=list_id

		output_data=generate_empty_json_object(output_schema)

		output_data['First Name']=first_name
		output_data['Last Name']=last_name
		output_data['PersonBioId']=personBioId
		output_data['LicenseNumber']=licenseNumber
		output_data['LicenseTypeCode']=licenseTypeCode
		output_data['LicenseStatus']=licenseStatus

		####	Fetch detail information for person
		logging.debug('Before detail page ping')
		while True:
			try:
				time.sleep(random.randint(json_config['min_sleep'],json_config['max_sleep']))
				obj = content_fetch(url=json_config['detail_page']['url'],method='post',post_param=detail_post_param,headers=json_config['detail_page']['headers'])
				if obj==1:
					logging.error('Content fetch error')
					continue
				# with open(f'Cache/{list_id}.html','wb') as fh:
					# fh.write(obj.content)
				detail_content=obj.text
				if not re.search('<title[^>]*?>\s*FAA\s*-\s*Unhandled\s*Error\s*<\/title>',detail_content,flags=re.I):
					break
				print('\nRe-Try to fetch content')
			except:
				logging.error(traceback.format_exc())

		medical_class=replace(regex_match(json_config['output_regex']['Medical Class'],detail_content))
		medical_date=replace(regex_match(json_config['output_regex']['Medical Date'],detail_content))

		basicmed_course_date=replace(regex_match(json_config['output_regex']['BasicMed Course Date'],detail_content))
		basicmed_cmec_date=replace(regex_match(json_config['output_regex']['BasicMed CMEC Date'],detail_content))

		personalIfoBlock=regex_match(json_config['output_regex']['personal_info_block'],detail_content)
		name=replace(regex_match(json_config['output_regex']['Name'],personalIfoBlock))
		splitted_name=re.split('\s+',name)
		if len(splitted_name[-1])<=2 and len(splitted_name)>2:
			output_data['First Name']=' '.join(splitted_name[:-2])
			output_data['Last Name']=' '.join(splitted_name[-2:])
		else:
			output_data['First Name']=' '.join(splitted_name[:-1])
			output_data['Last Name']=splitted_name[-1]
		output_data['Name']=name
		output_data['Address']=replace(regex_match(json_config['output_regex']['Address'],personalIfoBlock))
		output_data['State']=replace(regex_match(json_config['output_regex']['State'],personalIfoBlock))
		output_data['Address']=re.sub('\s+',' ',output_data['Address'])
		output_data['County']=replace(regex_match(json_config['output_regex']['County'],personalIfoBlock))
		output_data['Country']=replace(regex_match(json_config['output_regex']['Country'],personalIfoBlock))
		output_data['Medical Class']=medical_class
		output_data['Medical Date']=medical_date
		output_data['BasicMed Course Date']=basicmed_course_date
		output_data['BasicMed CMEC Date']=basicmed_cmec_date
		

		cert_blocks=re.findall(json_config['output_regex']['Certificate'],detail_content,flags=re.I)
		output_data['Certificate']=[].copy()
		if len(cert_blocks)>0:
			for cert_block in cert_blocks:
				certificate={}
				# date_of_issue=replace(regex_match('<b[^>]*?>\s*Date\s*of\s*Issue\s*:\s*<\/b>(?:\s|&nbsp;)*?(\d+\/\d+\/\d+)(?:\s|&nbsp;)*?<',cert_block))
				issue_month=regex_match(json_config['output_regex']['IssueMonth'],cert_block)
				issue_day=regex_match(json_config['output_regex']['IssueDay'],cert_block)
				issue_year=regex_match(json_config['output_regex']['IssueYear'],cert_block)
				license_type_name=replace(regex_match(json_config['output_regex']['LicenseTypeName'],cert_block))
				ratings=regex_match(json_config['output_regex']['Ratings'],cert_block)
				ratings=[replace(rating) for rating in re.split('<br\/>',ratings,flags=0) if replace(rating)!='']
				type_ratings=regex_match(json_config['output_regex']['Type Ratings'],cert_block)
				type_ratings=[replace(type_rating) for type_rating in re.split('<\/td>',type_ratings,flags=0) if replace(type_rating)!='']
				limits=replace(regex_match(json_config['output_regex']['Type Ratings'],cert_block))
				certificate['LicenseTypeName']=license_type_name
				certificate['IssueYear']=issue_year
				certificate['IssueMonth']=issue_month
				certificate['IssueDay']=issue_day
				certificate['Ratings']=ratings
				certificate['Type Ratings']='|'.join(type_ratings)
				certificate['Limit']=limits
				output_data['Certificate'].append(certificate)
		full_output_data.append(output_data)
		count+=1
	# print(count)
	if count==0:
		####	Got no result for search result
		output_data=generate_empty_json_object(output_schema)
		output_data={'Name':'','First Name':first_name,'Last Name':last_name,'State':'','Address':'','Country':'','County':'','PersonBioId':personBioId,'Medical Class':'','Medical Date':'','Certificate':[],'LicenseNumber':licenseNumber,'LicenseTypeCode':licenseTypeCode,'LicenseStatus':licenseStatus,'BasicMed Course Date':'','BasicMed CMEC Date':'','Comments':'No Result'}
		output_data['First Name']=first_name
		output_data['Last Name']=last_name
		output_data['PersonBioId']=personBioId
		output_data['LicenseNumber']=licenseNumber
		output_data['LicenseTypeCode']=licenseTypeCode
		output_data['LicenseStatus']=licenseStatus
		output_data['Comments']='No Result'
		# output_data=json_config['output_template'].copy()
		full_output_data.append(output_data)
	logging.info('Exit from Search Data Function')
	return full_output_data,count


# Send summary mail through SNS
def summary_report(message,subject):
	logging.info('Inside summary_report function')
	sns = boto3.client('sns', aws_access_key_id=os.environ['ACCESS_KEY'], aws_secret_access_key=os.environ['SECRET_KEY'])
	topic_arn = os.environ['SNS_TOPIC_URI']
	response = sns.publish(
		TopicArn=topic_arn,
		Message=message,
		MessageStructure='html',
		Subject=subject
	)


####	Check configuration file exists or not
if not os.path.exists('airmeninquiry_config.json'):
	print('FAILURE : Please place the airmeninquiry_config.json in script path')
	sys.exit(1)

try:
	json_config=json.load(open('airmeninquiry_config.json','r'))
except:
	print(traceback.format_exc())
	print('FAILURE : Issue in airmeninquiry_config.json file content format. Please check and fix.')
	sys.exit(1)


################	Scripts Log	###########################
log_config=json_config['log_config']

dictConfig(log_config)
logging.info('Script Start')

####	Session object create
logging.info('Session object create')
sess=requests.Session()
sess.headers['User-Agent']=json_config['useragent']

session_id=''
output_schema=''

proxy={'http': f'http://{os.environ["CRAWLERA_KEY"]}:@proxy.crawlera.com:{os.environ["CRAWLERA_PORT"]}/','https': f'http://{os.environ["CRAWLERA_KEY"]}:@proxy.crawlera.com:{os.environ["CRAWLERA_PORT"]}/',}

def lambda_handler(event, context):
	global session_id,output_schema
	try:
	
		sqs = boto3.client('sqs', aws_access_key_id=os.environ['ACCESS_KEY'], aws_secret_access_key=os.environ['SECRET_KEY'])
		#	Read input from SQS
		messages = event['Records']
		# response = sqs.receive_message(
			# QueueUrl=os.environ['INPUT_QUEUE_URL'],
			# MaxNumberOfMessages=1,
			# WaitTimeSeconds=5
		# )
		# for message in response['Messages']:
		for message in messages:
			input_datas = message['body']
			receipt_handle = message['receiptHandle']
			sqs.delete_message(
				QueueUrl=os.environ['INPUT_QUEUE_URL'],
				ReceiptHandle=receipt_handle
			)

			#	Parse the input using json parser
			try:
				input_data=json.loads(input_datas)
			except:
				logging.error('FAILURE : Invalid input format. Please check {}. Input should be json format'.format(re.sub('\n',' ',input_datas)))
				continue

			#	Download output schema from s3
			s3 = boto3.client('s3', aws_access_key_id=os.environ['ACCESS_KEY'], aws_secret_access_key=os.environ['SECRET_KEY'])
			response = s3.get_object(Bucket=os.environ['BUCKET_NAME'], Key=os.environ['SCHEMA_PATH'])
			output_schema=json.loads(response['Body'].read().decode('utf-8'))

			#	Validate mandatory data are in input
			if 'firstName' not in input_data or 'lastName' not in input_data or 'personBioId' not in input_data or 'licenseNumber' not in input_data or 'licenseTypeCode' not in input_data or 'licenseStatus' not in input_data:
				logging.error('FAILURE : firstName, lastName, personBioId, licenseNumber, licenseTypeCode and licenseStatus are mandatory data in given input {}. Please check whether it is missing or not'.format(re.sub('\n',' ',input_datas)))
				continue
			logging.debug('Process the input {}'.format(re.sub('\n',' ',input_datas)))

			full_output_data,number_of_results = get_search_data(input_data)
			obj = requests.delete('http://proxy.zyte.com:8011/sessions/'+session_id, auth=(os.environ['CRAWLERA_KEY'], ''))
			for output_data in full_output_data:
				try:
					jsonschema.validate(output_data, output_schema)
					message_deduplication_id = str(uuid.uuid4())
					response = sqs.send_message(QueueUrl=os.environ['OUTPUT_QUEUE_URL'],MessageBody=json.dumps(output_data),MessageGroupId=json_config['msg_group_id'],MessageDeduplicationId=message_deduplication_id)
				except jsonschema.exceptions.ValidationError as e:
					logging.error('FAILURE : invalid json schema output\n'+json.dumps(output_data))
			if number_of_results==-1:
				summary_report('Hello,\n\n\tAirmeninquiry website is currently un-available,due to scheduled maintenance. Please try again after some time.\n\nThanks,\nBot Team','Airmeninquiry Bot Summary')
			elif number_of_results==0:
				summary_report(f'Hello,\n\nAirmeninquiry bot run completed successfully with no result.\n\n\tInput First Name\t:\t{input_data["firstName"]}\n\tInput Last Name\t:\t{input_data["lastName"]}\n\nThanks,\nBot Team','Airmeninquiry Bot Summary')
			else:
				summary_report(f'Hello,\n\nAirmeninquiry bot run completed successfully and please find below the summary.\n\n\tInput First Name\t:\t{input_data["firstName"]}\n\tInput Last Name\t:\t{input_data["lastName"]}\n\tNumber of Results\t:\t{number_of_results}\n\nThanks,\nBot Team','Airmeninquiry Bot Summary')
	except:
		logging.error('FAILURE : Bot terminated with runtime error')
		logging.error(traceback.format_exc())
		summary_report('Hello,\n\n\tAirmeninquiry bot with runtime error. Kindly check and take necessary action.\n\nThanks,\nBot Team','Airmeninquiry Bot Summary')
	logging.debug('Script Run process Complete')