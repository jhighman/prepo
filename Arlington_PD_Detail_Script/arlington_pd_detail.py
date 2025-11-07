####	Used modules
import re
import json
import os
from urllib.parse import urljoin
import base64
import time
import datetime
import sys
import random
import traceback
import uuid
import logging
import jsonschema
from logging.config import dictConfig
import warnings
import boto3
warnings.filterwarnings("ignore")


import requests
from bs4 import BeautifulSoup


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


####	get anticaptcha result for task id
def ac_task_result(task_id):
	logging.info('Inside AC Task Result Function')
	retry=1
	while True:
		obj=requests.post(json_config['anticaptcha']['result_url'],json={'clientKey':os.environ['ANTICAPTCHA_KEY'],'taskId':task_id},headers=json_config['anticaptcha']['headers'])
		logging.info(f'AC Task Result Response Code : {obj.status_code}')
		if re.search('^2',str(obj.status_code)):
			result_response=obj.json()
			if result_response['errorId']==0 and result_response['status']=='ready':
				return result_response['solution']['gRecaptchaResponse']
			elif result_response['errorId']==1:
				return 'Captcha Result Error'
			if retry<6:
				time.sleep(10)
				retry+=1
			else:
				return 'Captcha Result Error'
		else:
			return 'Captcha Result Response Error'


####	captcha image request sent and get task id
# def ac_create_task(img_base64):
def ac_create_task(website_url,website_key):
	logging.info('Inside AC Task Create Function')
	task_parameter=json_config['anticaptcha']['task_parameter']
	task_parameter['clientKey'] = os.environ['ANTICAPTCHA_KEY']
	task_parameter['task']['websiteURL']=website_url
	task_parameter['task']['websiteKey']=website_key
	obj=requests.post(json_config['anticaptcha']['task_url'],json=task_parameter,headers=json_config['anticaptcha']['headers'])
	logging.debug(f'AC Task Create Response Code : {obj.status_code}')
	if re.search('^2',str(obj.status_code)):
		task_response=obj.json()
		if task_response['errorId']==0:
			time.sleep(15)
			return ac_task_result(task_response['taskId'])
		else:
			logging.debug(f'AC raised issue {task_response["errorCode"]}. Please fix the AC issue accordingly.')
			return 'Captcha Task Error'
	else:
		return 'Captcha Task Response Error'


####	content fetch from url
def content_fetch(url='',method='get',headers={},post_param={}):
	logging.info('Inside Content Fetch Function')
	logging.debug(f'URL:{url}, Method:{method}, Header:{headers}, Parameter:{post_param}')
	retry=0
	while retry<3:
		try:
			if method=='get':
				obj = sess.get(url,headers=headers)
			else:
				obj = sess.post(url,data=post_param,headers=headers)
			logging.info(f'Response Code : {obj.status_code}')
			if re.search('^2',str(obj.status_code)):
				return obj
			elif re.search('^5',str(obj.status_code)):
				time.sleep(10)
			else:
				return obj
			retry+=1
		except:
			logging.debug(traceback.format_exc())
			time.sleep(10)
	return 1


####	Public Repor Page Data Extraction for each case number
def get_public_report_data(input_data):
	logging.info('Inside Public Report Function')
	caseno=input_data['criminal']['arrest']['caseNumber']
	full_name=input_data['name']['fullName']
	logging.info('Inside Public Report Function')
	i=1
	while True:
		try:
			logging.debug('Content fetch for public report home page')
			obj = content_fetch(url=json_config['public_report']['url'],headers=json_config['public_report']['headers'])
			if obj==1:
				logging.debug(f'Retry to fetch content for Public Report {caseno}')
				time.sleep(30)
				continue
			public_report_base_content=obj.text
			option_post_param=json_config['public_report']['option_post_param']
			option_post_param_reg=json_config['public_report']['option_post_param_reg']
			for post_param_key in option_post_param_reg.keys():
				option_post_param[post_param_key]=regex_match(option_post_param_reg[post_param_key],public_report_base_content)
			logging.debug('Content fetch to select the case number option')
			obj = content_fetch(url=json_config['public_report']['url'],method='post',post_param=option_post_param,headers=json_config['public_report']['headers'])
			if obj==1:
				logging.debug('Retry to fetch content for Public Report Case number option selection')
				time.sleep(30)
				continue
			public_report_option_selected_content=obj.text
			break
		except:
			logging.debug(traceback.format_exc())
	while True:
		try:
			caseno_search_post_param=json_config['public_report']['caseno_search_post_param']
			caseno_search_post_param_reg=json_config['public_report']['caseno_search_post_param_reg']
			for caseno_search_post_param_key in caseno_search_post_param_reg.keys():
				caseno_search_post_param[caseno_search_post_param_key]=regex_match(caseno_search_post_param_reg[caseno_search_post_param_key],public_report_option_selected_content)
			site_key=regex_match(json_config['public_report']['site_key_reg'],public_report_option_selected_content)
			recaptcha_response = ac_create_task(json_config['public_report']['url'],site_key)
			caseno_search_post_param['g-recaptcha-response']=recaptcha_response
			caseno_search_post_param['txtCaseNumber']=caseno
			logging.debug(f'Content fetch for detail content for the case number : {caseno}')
			obj = content_fetch(url=json_config['public_report']['url'],method='post',post_param=caseno_search_post_param,headers=json_config['public_report']['headers'])
			if obj==1:
				logging.debug(f'Retry to fetch content for {caseno}')
				time.sleep(30)
				continue
			public_report_content=obj.text
			# with open(f'{cache_path}Public_Report_{caseno}.html','wb') as fh:
				# fh.write(obj.content)
			public_report_content=re.sub('<td[^>]*?;visibility:hidden;[^>]*?>\s*The\s*submitted\s*code\s*is\s*incorrect\s*<\/td>','',public_report_content,flags=re.I)
			if not re.search(json_config['captcha_fail_regex'],public_report_content,flags=re.I):
				break
			logging.debug('\nCaptcha attempt failed. Going to retry')
			public_report_option_selected_content=obj.text
		except:
			logging.debug(traceback.format_exc())
	logging.debug(f'Public report data extraction for {caseno}')
	
	search_caseno = regex_match(json_config['output_regex']['public_report_case_number'],public_report_content)
	if search_caseno=='':
		# soup=BeautifulSoup(public_report_content,'html.parser')
		streetAddress=replace(regex_match(json_config['output_regex']['street_address'],public_report_content))
		city=replace(regex_match(json_config['output_regex']['city'],public_report_content))
		offense_description_block=regex_match(json_config['output_regex']['offense_description_block'],public_report_content)
		offense_description=re.findall(json_config['output_regex']['offense_description'],offense_description_block,flags=re.I)
		for ind in range(0,len(offense_description)):
			offense_description[ind]={'description':replace(offense_description[ind])}
		personal_info_rows=re.findall(json_config['output_regex']['personal_info_rows'],public_report_content)
		arrest_description = replace(regex_match(json_config['output_regex']['arrest_description'],public_report_content))
		input_data['criminal']['location']['streetAddress']=streetAddress
		input_data['criminal']['location']['city']=city
		input_data['criminal']['offenses']=offense_description
		input_data['criminal']['arrest']['description']=arrest_description
		
		# print(f'{streetAddress}  ::  {city}  ::  {offense_description}')
		for personal_info_row in personal_info_rows:
			name=replace(regex_match(json_config['output_regex']['public_report_full_name'],personal_info_row)).upper()
			age=regex_match(json_config['output_regex']['age'],personal_info_row)
			# print(f'{name}  ::  {age}')
			if name=='STATE OF TEXAS,' or name!=full_name:
				continue
			input_data['dateOfBirth']['age']=age
	logging.info('Exit from Public Report Function')
	return input_data


# Define a function to recursively generate an empty JSON object
def generate_empty_json_object(schema):
    if schema["type"] == "object":
        return {k: generate_empty_json_object(v) for k, v in schema.get("properties", {}).items()}
    elif schema["type"] == "array":
        return []
    else:
        return ""


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
if not os.path.exists('arlington_pd_detail_config.json'):
	print('FAILURE : Please place the arlington_pd_detail_config.json in script path')
	sys.exit(1)


try:
	json_config=json.load(open('arlington_pd_detail_config.json','r'))
except:
	print(traceback.format_exc())
	print('FAILURE : Issue in arlington_pd_detail_config.json file content format. Please check and fix.')
	sys.exit(1)


################	Scripts Log	###########################
log_config=json_config['log_config']

dictConfig(log_config)
logging.info('Script Start')

####	Session object create
logging.info('Session object create')
sess = requests.Session()
sess.headers['User-Agent']=json_config['useragent']

def lambda_handler(event, context):
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
				logging.error(f'FAILURE : Invalid input format. Please check {input_datas}. Input should be json format')
				continue

			#	Download output schema from s3
			s3 = boto3.client('s3', aws_access_key_id=os.environ['ACCESS_KEY'], aws_secret_access_key=os.environ['SECRET_KEY'])
			response = s3.get_object(Bucket=os.environ['BUCKET_NAME'], Key=os.environ['SCHEMA_PATH'])
			output_schema=json.loads(response['Body'].read().decode('utf-8'))

			#	Validate the input schema
			try:
				jsonschema.validate(input_data, output_schema)
			except:
				logging.error(f'FAILURE : Invalid input schema. Please check {input_datas}.')
				continue
			logging.info(f'Process the input {input_datas}')

			#	Call case number search function
			json_output=get_public_report_data(input_data)

			#	Validate the output against output schema
			try:
				jsonschema.validate(json_output, output_schema)
				message_deduplication_id = str(uuid.uuid4())
				response = sqs.send_message(QueueUrl=os.environ['OUTPUT_QUEUE_URL'],MessageBody=json.dumps(json_output),MessageGroupId=json_config['msg_group_id'],MessageDeduplicationId=message_deduplication_id)
				# with open(f'Output/{caseNumber}.json','w',encoding='utf-8') as fh:
					# json.dump(json_output,fh,indent=4)
			except jsonschema.exceptions.ValidationError as e:
				logging.error('FAILURE : invalid json schema output\n'+json.dumps(json_output))
				# break
	except:
		logging.error('FAILURE : Bot terminated with runtime error')
		logging.error(traceback.format_exc())
		summary_report('Hello,\n\n\tArlington PD detail bot with runtime error. Kindly check and take necessary action.\n\nThanks,\nBot Team','Arlington PD Detail Bot Summary')
	logging.info('Script completed')