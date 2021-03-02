# Copyright 2017 Amazon Web Services

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pygit2 import Keypair,credentials,discover_repository,Repository,clone_repository,RemoteCallbacks
from boto3 import client
from botocore.exceptions import ClientError
import os,stat
import shutil
from zipfile import ZipFile
import json
import logging

### If true the function will not include .git folder in the zip
exclude_git=True

### If true the function will delete all files at the end of each invocation, useful if you run into storage space constraints, but will slow down invocations as each invoke will need to checkout the entire repo
cleanup=False

key='enc_key'

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers[0].setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s'))
logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)

s3 = client('s3')
kms = client('kms')
cp = client('codepipeline')

actionTypeId = {
    'category': 'Source',
    'owner': 'Custom',
    'provider': 'CustomWebhookSourceAction',
    'version': '1'
}

def write_key(filename,contents):
    logger.info('Writing keys to /tmp/...')
    mode = stat.S_IRUSR | stat.S_IWUSR
    umask_original = os.umask(0)

    try:
        handle = os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT, mode), 'w')
    finally:
        os.umask(umask_original)

    handle.write(contents+'\n')
    handle.close()

def get_keys(keybucket,update=False):
    if not os.path.isfile('/tmp/id_rsa') or not os.path.isfile('/tmp/id_rsa.pub') or update:
        logger.info('Keys not found on Lambda container, fetching from S3...')
        enckey = s3.get_object(Bucket=keybucket,Key=key)['Body'].read()
        privkey = kms.decrypt(CiphertextBlob=enckey)['Plaintext']
        pubkey = s3.get_object(Bucket=keybucket,Key='pub_key')['Body'].read()

        write_key('/tmp/id_rsa',privkey)
        write_key('/tmp/id_rsa.pub',pubkey)

    return Keypair('git','/tmp/id_rsa.pub','/tmp/id_rsa','')

def init_remote(repo, name, url):
    remote = repo.remotes.create(name, url, '+refs/*:refs/*')
    return remote

def create_repo(repo_path, remote_url, creds):
    if os.path.exists(repo_path):
            logger.info('Cleaning up repo path...')
            shutil.rmtree(repo_path)

    repo = clone_repository(remote_url, repo_path, callbacks=creds )
    return repo

def pull_repo(repo, remote_url, branch, creds):
    remote_exists = False

    for r in repo.remotes:
        if r.url == remote_url:
            remote_exists = True
            remote = r

    if not remote_exists:
        remote = repo.create_remote('origin',remote_url)

    logger.info('Fetching and merging changes...')
    remote.fetch(callbacks=creds)
    remote_master_id = repo.lookup_reference('refs/remotes/origin/' + branch).target
    repo.checkout_tree(repo.get(remote_master_id))
    master_ref = repo.lookup_reference('refs/heads/' + branch)
    master_ref.set_target(remote_master_id)
    repo.head.set_target(remote_master_id)
    return repo

def zip_repo(repo_path,repo_name):
    logger.info('Creating zipfile...')
    zf = ZipFile('/tmp/'+repo_name.replace('/','_')+'.zip','w')

    for dirname, subdirs, files in os.walk(repo_path):
        if exclude_git:
            try:
                subdirs.remove('.git')
            except ValueError:
                pass
        zdirname = dirname[len(repo_path)+1:]
        zf.write(dirname,zdirname)
        for filename in files:
            zf.write(os.path.join(dirname, filename),os.path.join(zdirname, filename))

    zf.close()
    return '/tmp/'+repo_name.replace('/','_')+'.zip'

def push_s3(filename,repo_name,outputbucket,s3key):
    logger.info('pushing zip to s3://%s/%s' % (outputbucket,s3key))
    data=open(filename,'rb')
    s3.put_object(Bucket=outputbucket,Body=data,Key=s3key)
    logger.info('Completed S3 upload...')

def pull(job):
    keybucket=os.environ['KEYS_BUCKET']
    outputbucket=job['data']['outputArtifacts'][0]['location']['s3Location']['bucketName']
    outputKey=job['data']['outputArtifacts'][0]['location']['s3Location']['objectKey']

    repo_name = job['data']['pipelineContext']['pipelineName'] 
    remote_url = job['data']['actionConfiguration']['configuration']['GitUrl']
    branch = job['data']['actionConfiguration']['configuration']['Branch']
    repo_path = '/tmp/%s' % repo_name
    creds = RemoteCallbacks( credentials=get_keys(keybucket), )

    try:
        repository_path = discover_repository(repo_path)
        repo = Repository(repository_path)
        logger.info('found existing repo, using that...')
    except:
        logger.info('creating new repo for %s in %s' % (remote_url, repo_path))
        repo = create_repo(repo_path, remote_url, creds)

    pull_repo(repo,remote_url,branch,creds)
    zipfile = zip_repo(repo_path, repo_name)
    push_s3(zipfile,repo_name,outputbucket,outputKey)

    commit = repo.head.get_object()
    revision = str(commit.id)
    commit_message = commit.message
    created = commit.commit_time

    currentRevision = {
        'revision': revision,
        'changeIdentifier': '???',
        'created': created,
        'revisionSummary': commit_message
    }

    if cleanup:
        logger.info('Cleanup Lambda container...')
        shutil.rmtree(repo_path)
        shutil.rm(zipfile)
        shutil.rm('/tmp/id_rsa')
        shutil.rm('/tmp/id_rsa.pub')
    
    return currentRevision

def lambda_handler(event,context):
    actionTypeId['version'] = os.environ['CUSTOM_ACTION_VERSION']
    actionTypeId['provider'] = os.environ['CUSTOM_ACTION_PROVIDER']
    print('Polling for jobs!')
    response = cp.poll_for_jobs(actionTypeId=actionTypeId, maxBatchSize=100)
    print('Received {} jobs!'.format(len(response['jobs'])))

    for job in response['jobs']:
        print('Processing job ID {}'.format(job['id']))
        
        try:
            ack_response = cp.acknowledge_job(jobId=job['id'], nonce=job['nonce'])
            
            if ack_response['status'] == 'InProgress':
                print('Acknowledged job id {}'.format(job['id']))
                currentRevision = pull(job)
                cp.put_job_success_result(jobId=job['id'], currentRevision=currentRevision )
        except Exception as e:
            cp.put_job_failure_result(jobId=job['id'], failureDetails={ 'type': 'JobFailed', 'message': str(e)})
            print('Error: ' + str(e))
