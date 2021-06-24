import json
import os
import uuid

from .fixtures.gcp import *


def test_gcp_project_add_and_remove(polaris_client):
    # Load test project information from file

    f = open(os.environ['SDK_GCPPROJECT_FILE'],)
    gcp_project_details = json.load(f)

    # Add default GCP service account to Polaris

    sa_name = 'gcp-sa-'+str(uuid.uuid4())
    current_sa_name = polaris_client.get_account_gcp_default_sa()

    assert sa_name != current_sa_name

    polaris_client.set_account_gcp_default_sa(service_account_auth_key_file=os.environ['GOOGLE_APPLICATION_CREDENTIALS'], 
                                              service_account_name=sa_name)

    assert sa_name == polaris_client.get_account_gcp_default_sa()

    # Add the project to Polaris

    polaris_client.add_project_gcp(gcp_native_project_id=gcp_project_details['projectId'], 
                                   gcp_native_project_name=gcp_project_details['projectName'], 
                                   gcp_native_project_number=gcp_project_details['projectNumber'])

    # Verify that the project was successfully added.

    project = polaris_client.get_accounts_gcp(gcp_project_details['projectId'])

    assert project[0]['gcp_native_project_id'] == gcp_project_details['projectId']
    assert project[0]['gcp_native_project_name'] == gcp_project_details['projectName']
    assert project[0]['gcp_native_project_number'] == gcp_project_details['projectNumber']

    # Delete project from Polaris

    polaris_client.delete_project_gcp(gcp_native_project_id=gcp_project_details['projectId'])

    # Verify that the project was successfully removed

    assert polaris_client.get_accounts_gcp(gcp_project_details['projectId']) == []
    

def test_find_and_assign_sla(polaris_client, gcp_project):
    bronze_sla_domain_id = polaris_client.get_sla_domains('Bronze')['id']

    assert bronze_sla_domain_id == '00000000-0000-0000-0000-000000000002'

    object_ids = polaris_client.get_compute_object_ids_gce(nativeName='ubuntu-fdse-shared-1')

    assert len(object_ids) == 1

    polaris_client.submit_assign_sla(object_ids=object_ids, 
                                     sla_id=bronze_sla_domain_id, 
                                     existing_snapshot_retention='KEEP_FOREVER')


def test_on_demand_snapshot(polaris_client, gcp_project):
    bronze_sla_domain_id = polaris_client.get_sla_domains('Bronze')['id']

    object_ids = polaris_client.get_compute_object_ids_gce(region='us-west1')

    assert len(object_ids) > 0

    polaris_client.submit_on_demand(object_ids, bronze_sla_domain_id, wait=True)

    for object_id in object_ids:
        snapshot = polaris_client.get_snapshots(object_id, recovery_point='latest')
        assert snapshot[0]['isOnDemandSnapshot']
