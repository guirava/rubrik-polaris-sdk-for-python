import json
import os
import pytest
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
from rubrik_polaris import rubrik_polaris


@pytest.fixture
def polaris_client():
    return rubrik_polaris.PolarisClient(json_keyfile=os.environ['RUBRIK_POLARIS_SERVICEACCOUNT_FILE'])


@pytest.fixture
def gcp_service_account(polaris_client):
    sa_name = 'gcp-sa-'+str(uuid.uuid4())
    polaris_client.set_account_gcp_default_sa(service_account_auth_key_file=os.environ['GOOGLE_APPLICATION_CREDENTIALS'], 
                                              service_account_name=sa_name)


@pytest.fixture
def gcp_project(polaris_client, gcp_service_account):
    # Load test project information from file

    f = open(os.environ['SDK_GCPPROJECT_FILE'],)
    gcp_project_details = json.load(f)

    # Add the project to Polaris

    polaris_client.add_project_gcp(gcp_native_project_id=gcp_project_details['projectId'], 
                                   gcp_native_project_name=gcp_project_details['projectName'], 
                                   gcp_native_project_number=gcp_project_details['projectNumber'])

    yield

    # Delete project from Polaris

    polaris_client.delete_project_gcp(gcp_native_project_id=gcp_project_details['projectId'])