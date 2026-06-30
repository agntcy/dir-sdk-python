# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
import json
import os
import pathlib
import subprocess
import threading
import time
import unittest
import uuid

import grpc
from agntcy.dir_sdk.client import Client
from agntcy.dir_sdk.models import (
    catalog_v1,
    core_v1,
    events_v1,
    routing_v1,
    search_v1,
    sign_v1,
    store_v1,
)


class TestClient(unittest.TestCase):
    def setUp(self) -> None:
        # Initialize the client
        self.client = Client()

    def test_push(self) -> None:
        records = self.gen_records(2, "push")
        record_refs = self.client.push(records=records)

        assert record_refs is not None
        assert isinstance(record_refs, list)
        assert len(record_refs) == 2

        for ref in record_refs:
            assert isinstance(ref, core_v1.RecordRef)
            assert len(ref.cid) == 59

    def test_pull(self) -> None:
        records = self.gen_records(2, "pull")
        record_refs = self.client.push(records=records)
        pulled_records = self.client.pull(refs=record_refs)

        assert pulled_records is not None
        assert isinstance(pulled_records, list)
        assert len(pulled_records) == 2

        for index, record in enumerate(pulled_records):
            assert isinstance(record, core_v1.Record)
            assert records[index] == record

    def test_lookup(self) -> None:
        records = self.gen_records(2, "lookup")
        record_refs = self.client.push(records=records)
        metadatas = self.client.lookup(record_refs)

        assert metadatas is not None
        assert isinstance(metadatas, list)
        assert len(metadatas) == 2

        for metadata in metadatas:
            assert isinstance(metadata, core_v1.RecordMeta)

    def test_publish(self) -> None:
        records = self.gen_records(1, "publish")
        record_refs = self.client.push(records=records)
        publish_request = routing_v1.PublishRequest(
            record_refs=routing_v1.RecordRefs(refs=record_refs),
        )

        self.client.publish(publish_request)

    def test_list(self) -> None:
        records = self.gen_records(1, "list")
        record_refs = self.client.push(records=records)
        self.client.publish(
            routing_v1.PublishRequest(
                record_refs=routing_v1.RecordRefs(refs=record_refs),
            )
        )

        # Sleep to allow the publication to be indexed
        time.sleep(5)

        # Query for records in the domain
        list_query = routing_v1.RecordQuery(
            type=routing_v1.RECORD_QUERY_TYPE_DOMAIN,
            value="technology/networking",
        )

        list_request = routing_v1.ListRequest(queries=[list_query])
        objects = list(self.client.list(list_request))

        assert objects is not None
        assert len(objects) != 0

        for o in objects:
            assert isinstance(o, routing_v1.ListResponse)

    def test_search(self) -> None:
        records = self.gen_records(1, "search")
        _ = self.client.push(records=records)

        search_query = search_v1.RecordQuery(
            type=search_v1.RECORD_QUERY_TYPE_SKILL_ID,
            value="10201",
        )

        search_request = search_v1.SearchCIDsRequest(queries=[search_query], limit=2)

        objects = list(self.client.search_cids(search_request))

        assert objects is not None
        assert len(objects) > 0

        for o in objects:
            assert isinstance(o, search_v1.SearchCIDsResponse)

    def test_search_annotation(self) -> None:
        records = [
            core_v1.Record(
                data={
                    "name": f"agntcy-annotation-{uuid.uuid4().hex[:8]}",
                    "version": "v3.0.0",
                    "schema_version": "0.8.0",
                    "description": "Record with custom annotations.",
                    "authors": ["AGNTCY"],
                    "created_at": "2025-03-19T17:06:37Z",
                    "annotations": {"key": "value"},
                    "skills": [
                        {
                            "name": "natural_language_processing/natural_language_generation/text_completion",
                            "id": 10201,
                        }
                    ],
                    "locators": [],
                    "domains": [{"name": "technology/networking", "id": 103}],
                    "modules": [],
                }
            )
        ]
        record_refs = self.client.push(records=records)
        assert len(record_refs) == 1

        search_query = search_v1.RecordQuery(
            type=search_v1.RECORD_QUERY_TYPE_ANNOTATION,
            value="key:value",
        )
        search_request = search_v1.SearchCIDsRequest(queries=[search_query], limit=10)
        objects = self.client.search_cids(search_request)

        assert any(o.record_cid == record_refs[0].cid for o in objects)

    def test_search_routing(self) -> None:
        records = self.gen_records(1, "search_routing")
        record_refs = self.client.push(records=records)

        self.client.publish(
            routing_v1.PublishRequest(
                record_refs=routing_v1.RecordRefs(refs=record_refs),
            )
        )

        time.sleep(5)

        search_query = routing_v1.RecordQuery(
            type=routing_v1.RECORD_QUERY_TYPE_DOMAIN,
            value="technology/networking",
        )
        search_request = routing_v1.SearchRequest(queries=[search_query], limit=10)
        objects = self.client.search_routing(search_request)

        assert objects is not None
        for obj in objects:
            assert isinstance(obj, routing_v1.SearchResponse)

    def test_delete_referrer(self) -> None:
        records = self.gen_records(1, "delete_referrer")
        record_refs = self.client.push(records=records)

        push_response = self.client.push_referrer(
            req=[
                store_v1.PushReferrerRequest(
                    record_ref=record_refs[0],
                    type=sign_v1.Signature.DESCRIPTOR.full_name,
                    data={
                        "signature": "dGVzdC1zaWduYXR1cmU=",
                        "annotations": {"payload": "test-payload-data"},
                    },
                )
            ]
        )
        assert len(push_response) == 1
        assert push_response[0].success

        delete_response = self.client.delete_referrer(
            store_v1.DeleteReferrerRequest(
                record=record_refs[0],
                referrer_ref=push_response[0].referrer_ref,
            )
        )
        assert delete_response is not None
        assert len(delete_response.referrer_refs) > 0

    def test_unpublish(self) -> None:
        records = self.gen_records(1, "unpublish")
        record_refs = self.client.push(records=records)

        publish_record_refs = routing_v1.RecordRefs(refs=record_refs)
        _ = routing_v1.PublishRequest(record_refs=publish_record_refs)
        unpublish_request = routing_v1.UnpublishRequest(record_refs=publish_record_refs)

        self.client.unpublish(unpublish_request)

    def test_delete(self) -> None:
        records = self.gen_records(1, "delete")
        record_refs = self.client.push(records=records)
        self.client.delete(record_refs)

    def test_push_referrer(self) -> None:
        records = self.gen_records(2, "push_referrer")
        record_refs = self.client.push(records=records)

        request = [
            store_v1.PushReferrerRequest(
                record_ref=record_refs[0],
                type=sign_v1.Signature.DESCRIPTOR.full_name,
                data={
                    "signature": "dGVzdC1zaWduYXR1cmU=",  # base64 encoded "test-signature"
                    "annotations": {"payload": "test-payload-data"},
                },
            ),
            store_v1.PushReferrerRequest(
                record_ref=record_refs[1],
                type=sign_v1.Signature.DESCRIPTOR.full_name,
                data={
                    "signature": "dGVzdC1zaWduYXR1cmU=",  # base64 encoded "test-signature"
                    "annotations": {"payload": "test-payload-data"},
                },
            ),
        ]

        response = self.client.push_referrer(req=request)

        assert response is not None
        assert len(response) == 2

        for r in response:
            assert isinstance(r, store_v1.PushReferrerResponse)

    def test_pull_referrer(self) -> None:
        records = self.gen_records(2, "pull_referrer")
        record_refs = self.client.push(records=records)

        # Push referrers to these records
        request = [
            store_v1.PushReferrerRequest(
                record_ref=record_refs[0],
                type=sign_v1.Signature.DESCRIPTOR.full_name,
                data={
                    "signature": "dGVzdC1zaWduYXR1cmU=",  # base64 encoded "test-signature"
                    "annotations": {"payload": "test-payload-data"},
                },
            ),
            store_v1.PushReferrerRequest(
                record_ref=record_refs[1],
                type=sign_v1.Signature.DESCRIPTOR.full_name,
                data={
                    "signature": "dGVzdC1zaWduYXR1cmU=",  # base64 encoded "test-signature"
                    "annotations": {"payload": "test-payload-data"},
                },
            ),
        ]
        response = self.client.push_referrer(req=request)
        assert response is not None
        assert len(response) == 2
        for r in response:
            assert isinstance(r, store_v1.PushReferrerResponse)

        pull_request = [
            store_v1.PullReferrerRequest(
                record_ref=record_refs[0],
                referrer_type=sign_v1.Signature.DESCRIPTOR.full_name,
            ),
            store_v1.PullReferrerRequest(
                record_ref=record_refs[1],
                referrer_type=sign_v1.Signature.DESCRIPTOR.full_name,
            ),
        ]

        pull_response = self.client.pull_referrer(req=pull_request)

        assert pull_response is not None
        assert len(pull_response) == 2

        for pull_r in pull_response:
            assert isinstance(pull_r, store_v1.PullReferrerResponse)

    def test_sign_and_verify(self) -> None:
        records = self.gen_records(2, "sign_verify")
        record_refs = self.client.push(records=records)

        # Remove existing cosign keys if any
        pathlib.Path("cosign.key").unlink(missing_ok=True)
        pathlib.Path("cosign.pub").unlink(missing_ok=True)

        # Prepare cosign key pair
        key_password = "testing-key"

        # Set environment variable for cosign password
        shell_env = os.environ.copy()
        shell_env["COSIGN_PASSWORD"] = key_password

        docker_config = self.client.config.docker_config
        if docker_config:
            docker_config.envs["COSIGN_PASSWORD"] = key_password

        # Generate a key pair using cosign
        cosign_path = os.getenv("COSIGN_PATH", "cosign")
        command = (cosign_path, "generate-key-pair")
        subprocess.run(command, check=True, capture_output=True, env=shell_env)

        if docker_config:
            cosign_key_path = pathlib.Path("cosign.key").absolute()
            cosign_pub_path = pathlib.Path("cosign.pub").absolute()
            docker_config.mounts.append(
                f"type=bind,src={cosign_key_path},dst=/cosign.key"
            )
            docker_config.mounts.append(
                f"type=bind,src={cosign_pub_path},dst=/cosign.pub"
            )

        # Prepare Key signing request using file path reference
        # The CLI will load the key from the file path directly
        key_provider = sign_v1.SignWithKey(
            private_key="cosign.key",
            password=key_password.encode("utf-8"),
        )

        request_key_provider = sign_v1.SignRequestProvider(key=key_provider)
        key_request = sign_v1.SignRequest(
            record_ref=record_refs[0],
            provider=request_key_provider,
        )

        # Prepare OIDC signing request
        token = shell_env.get("OIDC_TOKEN", "")
        provider_url = shell_env.get("OIDC_PROVIDER_URL", "")
        client_id = shell_env.get("OIDC_CLIENT_ID", "sigstore")

        sign_oidc_options = sign_v1.SignOptionsOIDC(
            oidc_provider_url=provider_url, oidc_client_id=client_id
        )
        oidc_provider = sign_v1.SignWithOIDC(id_token=token, options=sign_oidc_options)
        request_oidc_provider = sign_v1.SignRequestProvider(oidc=oidc_provider)
        oidc_request = sign_v1.SignRequest(
            record_ref=record_refs[1],
            provider=request_oidc_provider,
        )

        verify_oidc_options = sign_v1.VerifyOptionsOIDC()

        try:
            # Sign and verify using Key signing
            self.client.sign(key_request)

            # Sign and verify using OIDC signing if set
            if token and provider_url:
                self.client.sign(oidc_request)
            else:
                record_refs.pop()  # NOTE: Drop the unsigned record if no OIDC tested

            # Verification is asynchronous (reconciler caches results). Wait for it to run.
            time.sleep(8)

            for verify_index, ref in enumerate(record_refs):
                response = self.client.verify(
                    sign_v1.VerifyRequest(
                        record_ref=ref,
                        provider=sign_v1.VerifyRequestProvider(
                            any=sign_v1.VerifyWithAny(oidc_options=verify_oidc_options)
                        ),
                    )
                )

                assert response.success is True

                # Verify that signers array is present and not empty
                assert response.signers is not None
                assert len(response.signers) > 0

                # For the first record (key-signed), verify key signer info
                if verify_index == 0:
                    signer = response.signers[0]
                    assert signer.HasField("key"), (
                        "Expected key signer info for key-signed record"
                    )
                    assert signer.key.public_key, "Expected public key in signer info"
                    assert signer.key.algorithm, "Expected algorithm in signer info"

                # For OIDC-signed record, verify OIDC signer info
                if verify_index == 1 and token and provider_url:
                    signer = response.signers[0]
                    assert signer.HasField("oidc"), (
                        "Expected OIDC signer info for OIDC-signed record"
                    )
                    assert signer.oidc.issuer, "Expected issuer in OIDC signer info"
                    assert signer.oidc.subject, "Expected subject in OIDC signer info"

                # Response with from_server (cached) must match local verification
                from_server_response = self.client.verify(
                    sign_v1.VerifyRequest(record_ref=ref, from_server=True)
                )
                assert from_server_response.success == response.success
                assert from_server_response.signers is not None
                assert len(from_server_response.signers) == len(response.signers)
                for i in range(len(response.signers)):
                    r_signer = response.signers[i]
                    s_signer = from_server_response.signers[i]
                    assert r_signer.WhichOneof("type") == s_signer.WhichOneof("type")
                    if r_signer.HasField("key") and s_signer.HasField("key"):
                        assert s_signer.key.public_key == r_signer.key.public_key
                        assert s_signer.key.algorithm == r_signer.key.algorithm
                    if r_signer.HasField("oidc") and s_signer.HasField("oidc"):
                        assert s_signer.oidc.issuer == r_signer.oidc.issuer
                        assert s_signer.oidc.subject == r_signer.oidc.subject

        finally:
            pathlib.Path("cosign.key").unlink(missing_ok=True)
            pathlib.Path("cosign.pub").unlink(missing_ok=True)

        # Test invalid sign request
        invalid_request = sign_v1.SignRequest(
            record_ref=core_v1.RecordRef(cid="invalid-cid"),
            provider=request_key_provider,
        )
        with self.assertRaises(RuntimeError) as ctx:
            self.client.sign(invalid_request)
        self.assertIn("Failed to sign the object", str(ctx.exception))

    def test_sync(self) -> None:
        create_request = store_v1.CreateSyncRequest(
            remote_directory_url=os.getenv(
                "DIRECTORY_SERVER_PEER1_ADDRESS",
                "0.0.0.0:8891",
            ),
        )
        create_response = self.client.create_sync(create_request)

        uuid.UUID(create_response.sync_id)

        list_request = store_v1.ListSyncsRequest()
        list_response = self.client.list_syncs(list_request)

        for sync_item in list_response:
            assert isinstance(sync_item, store_v1.ListSyncsItem)
            uuid.UUID(sync_item.sync_id)

        get_request = store_v1.GetSyncRequest(sync_id=create_response.sync_id)
        get_response = self.client.get_sync(get_request)

        assert isinstance(get_response, store_v1.GetSyncResponse)
        assert get_response.sync_id == create_response.sync_id

        delete_request = store_v1.DeleteSyncRequest(sync_id=create_response.sync_id)
        self.client.delete_sync(delete_request)

    def test_listen(self) -> None:
        listen_request = events_v1.ListenRequest()
        listen_stream = self.client.listen(listen_request)
        events = []

        def cancel_stream() -> None:
            time.sleep(15)
            listen_stream.cancel()

        def read_stream() -> None:
            try:
                for response in listen_stream:
                    events.append(response)
            except grpc.RpcError as e:
                if e.code() != grpc.StatusCode.CANCELLED:
                    raise
            except Exception as e:
                msg = f"Failed to listen: {e}"
                raise RuntimeError(msg) from e

        cancel_thread = threading.Thread(target=cancel_stream)
        read_thread = threading.Thread(target=read_stream)

        cancel_thread.start()
        read_thread.start()

        event_records = self.gen_records(10, "listen")
        _ = self.client.push(records=event_records)

        cancel_thread.join()

        assert events is not None
        assert len(events) > 0

        for o in events:
            assert isinstance(o, events_v1.ListenResponse)

    def test_publication(self) -> None:
        records = self.gen_records(1, "publication")
        record_refs = self.client.push(records=records)

        create_request = routing_v1.PublishRequest(
            record_refs=routing_v1.RecordRefs(refs=record_refs),
        )

        create_response = self.client.create_publication(create_request)

        assert isinstance(create_response, routing_v1.CreatePublicationResponse)

        list_request = routing_v1.ListPublicationsRequest(limit=3)
        list_response = self.client.list_publication(list_request)

        for publication_item in list_response:
            assert isinstance(publication_item, routing_v1.ListPublicationsItem)

        get_request = routing_v1.GetPublicationRequest(
            publication_id=create_response.publication_id
        )
        get_response = self.client.get_publication(get_request)

        assert isinstance(get_response, routing_v1.GetPublicationResponse)
        assert get_response.publication_id == create_response.publication_id

    def test_resolve(self) -> None:
        # Push a record using built-in generator
        records = self.gen_records(1, "resolve")
        record_name = str(records[0].data["name"])
        record_version = str(records[0].data["version"])

        record_refs = self.client.push(records=records)
        assert len(record_refs) == 1

        # Resolve by name
        resolve_response = self.client.resolve(name=record_name)

        assert resolve_response is not None
        assert len(resolve_response.records) > 0
        assert resolve_response.records[0].cid == record_refs[0].cid
        assert resolve_response.records[0].name == record_name
        assert resolve_response.records[0].version == record_version

        # Resolve by name with version
        resolve_with_version_response = self.client.resolve(
            name=record_name, version=record_version
        )

        assert resolve_with_version_response is not None
        assert len(resolve_with_version_response.records) == 1
        assert resolve_with_version_response.records[0].cid == record_refs[0].cid

    def test_get_verification_info(self) -> None:
        # Push a record
        records = self.gen_records(1, "verification")
        record_refs = self.client.push(records=records)

        # Get verification info by CID (record is not signed, so it should return unverified)
        verify_response = self.client.get_verification_info(cid=record_refs[0].cid)

        assert verify_response is not None
        # Unsigned records should return verified=false
        assert verify_response.verified is False
        assert (
            verify_response.error_message is not None
            or verify_response.error_message == ""
        )

    def test_list_agents(self) -> None:
        cid = self._push_catalog_fixture()
        self._wait_for_catalog_entry(cid)

        response = self.client.list_agents(catalog_v1.ListAgentsRequest())

        assert isinstance(response, catalog_v1.ListAgentsResponse)
        assert any(entry.identifier.find(cid) != -1 for entry in response.results)
        assert any(
            entry.display_name == "burger_seller_agent" for entry in response.results
        )

    def test_get_agent(self) -> None:
        cid = self._push_catalog_fixture()
        self._wait_for_catalog_entry(cid)

        response = self.client.get_agent(catalog_v1.GetAgentRequest(cid=cid))

        assert isinstance(response, catalog_v1.GetAgentResponse)
        assert response.entry.identifier.find(cid) != -1

    def test_get_well_known_catalog(self) -> None:
        self._push_catalog_fixture()

        response = self.client.get_well_known_catalog(
            catalog_v1.GetWellKnownCatalogRequest()
        )

        assert isinstance(response, catalog_v1.GetWellKnownCatalogResponse)
        assert response.catalog.spec_version
        assert response.catalog.host.display_name

    def test_export_agent(self) -> None:
        cid = self._push_catalog_fixture()
        self._wait_for_catalog_entry(cid)

        response = self.client.export_agent(
            catalog_v1.ExportAgentRequest(cid=cid, format="oasf")
        )

        assert response.data

    def _push_catalog_fixture(self) -> str:
        fixture_path = pathlib.Path(__file__).parent / "testdata" / "record_100.json"
        with fixture_path.open(encoding="utf-8") as fixture_file:
            record_data = json.load(fixture_file)
        record_refs = self.client.push([core_v1.Record(data=record_data)])
        return record_refs[0].cid

    def _wait_for_catalog_entry(self, cid: str, timeout_sec: float = 30.0) -> None:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            response = self.client.list_agents(catalog_v1.ListAgentsRequest())
            if any(entry.identifier.find(cid) != -1 for entry in response.results):
                return
            time.sleep(1)
        msg = f"catalog entry for {cid} not found within {timeout_sec}s"
        raise AssertionError(msg)

    def gen_records(self, count: int, test_function_name: str) -> list[core_v1.Record]:
        """
        Generate test records with unique names.
        Schema: https://schema.oasf.outshift.com/0.7.0/objects/record
        """
        records: list[core_v1.Record] = [
            core_v1.Record(
                data={
                    "name": f"agntcy-{test_function_name}-{index}-{str(uuid.uuid4())[:8]}",
                    "version": "v3.0.0",
                    "schema_version": "0.7.0",
                    "description": "Research agent for Cisco's marketing strategy.",
                    "authors": ["Cisco Systems"],
                    "created_at": "2025-03-19T17:06:37Z",
                    "skills": [
                        {
                            "name": "natural_language_processing/natural_language_generation/text_completion",
                            "id": 10201,
                        },
                        {
                            "name": "natural_language_processing/analytical_reasoning/problem_solving",
                            "id": 10702,
                        },
                    ],
                    "locators": [
                        {
                            "type": "docker_image",
                            "url": "https://ghcr.io/agntcy/marketing-strategy",
                        }
                    ],
                    "domains": [{"name": "technology/networking", "id": 103}],
                    "modules": [],
                }
            )
            for index in range(count)
        ]

        return records

    @staticmethod
    def cancel_stream_after_delay(responses: grpc.Call, delay_sec: int = 5) -> None:
        # Wait before cancelling to simulate some condition or timeout
        time.sleep(delay_sec)
        print("Cancelling the stream...")
        responses.cancel()


if __name__ == "__main__":
    unittest.main()
