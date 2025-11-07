FROM public.ecr.aws/lambda/python:3.9

# Install the function's dependencies using file requirements.txt
# from your project folder.

COPY requirements.txt  .
RUN  pip3 install -r requirements.txt --target .

# Copy function code
COPY arlington_pd_detail_config.json .
COPY arlington_pd_detail.py .


# Set the CMD to your handler (could also be done as a parameter override outside of the Dockerfile)
CMD [ "arlington_pd_detail.lambda_handler" ]