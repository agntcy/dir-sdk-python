# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

from agntcy.dir_sdk.client import Client
from agntcy.dir_sdk.models import core_v1, routing_v1, search_v1
from google.protobuf.json_format import MessageToJson


def generate_record(name: str) -> core_v1.Record:
    return core_v1.Record(
        data={
            "name": name,
            "version": "v1.0.0",
            "schema_version": "0.8.0",
            "description": "My example agent",
            "authors": ["AGNTCY"],
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
            "annotations": {"env": "prod"},
            "modules": [
                {
                    "name": "integration/a2a",
                    "id": 203,
                    "data": {
                        "protocol_version": "lightweight orchestra moral",
                        "card_data": "centres",
                        "capabilities": [
                            "state_transition_history",
                            "push_notifications",
                        ],
                        "transports": ["grpc", "http"],
                        "output_modes": ["text/html"],
                    },
                }
            ],
        },
    )


def main() -> None:
    client = Client()

    records = [generate_record(x) for x in ["example-record", "example-record2"]]

    # Push objects to the store
    refs = client.push(records)

    for ref in refs:
        print("Pushed object ref:", ref.cid)

    # Pull objects from the store
    pulled_records = client.pull(refs)

    for pulled_record in pulled_records:
        print("Pulled object data:", MessageToJson(pulled_record))

    # Lookup the object
    metadatas = client.lookup(refs)

    for metadata in metadatas:
        print("Lookup object metadata:", MessageToJson(metadata))

    # Publish the object
    record_refs = routing_v1.RecordRefs(refs=[refs[0]])
    publish_request = routing_v1.PublishRequest(record_refs=record_refs)
    client.publish(publish_request)
    print("Object published.")

    # List objects in the store
    query = routing_v1.RecordQuery(
        type=routing_v1.RECORD_QUERY_TYPE_SKILL,
        value="/skills/Natural Language Processing/Text Completion",
    )

    list_request = routing_v1.ListRequest(queries=[query])
    listed_objects = client.list(list_request)

    for o in listed_objects:
        print("Listed object:", MessageToJson(o))

    # Search objects by version
    search_query = search_v1.RecordQuery(
        type=search_v1.RECORD_QUERY_TYPE_VERSION,
        value="v1.*",
    )

    search_request = search_v1.SearchCIDsRequest(queries=[search_query], limit=3)
    search_results = client.search_cids(search_request)

    print("Searched objects:", search_results)

    # Search objects by annotation key:value (v1.4)
    annotation_query = search_v1.RecordQuery(
        type=search_v1.RECORD_QUERY_TYPE_ANNOTATION,
        value="env:prod",
    )
    annotation_results = client.search_cids(
        search_v1.SearchCIDsRequest(queries=[annotation_query], limit=3),
    )
    print("Annotation search results:", annotation_results)

    # Unpublish the object
    record_refs = routing_v1.RecordRefs(refs=[refs[0]])
    unpublish_request = routing_v1.UnpublishRequest(record_refs=record_refs)
    client.unpublish(unpublish_request)
    print("Object unpublished.")

    # Delete the object
    client.delete(refs)
    print("Objects are deleted.")


if __name__ == "__main__":
    main()
