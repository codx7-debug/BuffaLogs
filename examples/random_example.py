import argparse
import json
import os
import random
from datetime import datetime, timedelta

import yaml
from django.conf import settings
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from impossible_travel.ingestion.ingestion_factory import IngestionFactory

NUM_LOGS = 2000


def _get_ingestion_config(ingestion_source):
    with open(
        os.path.join(settings.CERTEGO_BUFFALOGS_CONFIG_PATH, "buffalogs/ingestion.json"),
        mode="r",
        encoding="utf-8",
    ) as f:
        config = json.load(f)
    if not config.get(config[ingestion_source]):
        raise ValueError(f"The configuration for the {config[ingestion_source]} must be implemented")
    return config


def load_elasticsearch_data(config):
    """Generate random example data for the Elasticsearch ingestion source"""
    data = []

    for _ in range(NUM_LOGS):
        # TODO: integrate all the current fields
        msg = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": f"192.168.1.{random.randint(1, 255)}",
            "destination_ip": f"10.0.0.{random.randint(1, 255)}",
            "action": random.choice(["ALLOW", "DENY"]),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        }
        data.append(msg)
    es = Elasticsearch(config)
    write_bulk(es, "fw-proxy", data)
    return data


def main():
    parser = argparse.ArgumentParser(description="Script to generate random data for the defined ingestion source")

    # TODO: this should be something like this (dynamic, not static as now): [source.value for source in BaseIngestion.SupportedIngestionSources]
    ingestion_choices = {
        "elasticsearch": load_elasticsearch_data,
    }

    parser.add_argument(
        "--ingestion-source",
        type=str,
        default="elasticsearch",
        choices=ingestion_choices.keys(),
        help=f"Ingestion source on which to load random_example data (default: elasticsearch). Available options: {', '.join(ingestion_choices.keys())}",
    )

    args = parser.parse_args()

    # Generate data based on the specified --ingestion-source in the command
    ingestion_config = _get_ingestion_config(ingestion_source=args.ingestion_source)
    data = ingestion_choices[args.ingestion_source](config=ingestion_config)

    print(f"Generated data for {args.ingestion_source}:")


if __name__ == "__main__":
    main()


def generate_common_data():
    fields = []
    event_outcome = ["failure"] * 10 + ["success"] * 90
    event_category = ["threat"] * 2 + ["session"] * 2 + ["malware"] * 6 + ["authentication"] * 90
    event_type = ["start"] * 80 + ["end"] * 20

    with open("random_data.yaml", "r", encoding="utf-8") as info:
        read_data = yaml.load(info, Loader=yaml.FullLoader)

    for _ in range(0, NUM_LOGS):
        tmp = {}
        ip = random.choice(read_data["ip"])
        now = datetime.now()
        str_time = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        head = str_time[:-4]
        tail = str_time[-1:]
        tmp["@timestamp"] = head + tail

        tmp["user"] = {"name": random.choice(read_data["user_name"])}
        tmp["event"] = {
            "outcome": random.choice(event_outcome),
            "category": random.choice(event_category),
            "type": random.choice(event_type),
        }
        tmp["source"] = {
            "ip": ip["address"],
            "geo": {
                "country_name": ip["country_name"],
            },
        }
        tmp["source"]["geo"]["location"] = {
            "lat": ip["latitude"],
            "lon": ip["longitude"],
        }
        tmp["user_agent"] = {"original": random.choice(read_data["user_agent"])}
        tmp["source"]["as"] = {"organization": {"name": ip["organization"]}}
        now = now + timedelta(seconds=1)
        fields.append(tmp)
    return fields


def write_bulk(es, index, msg_list):
    """Save a list of messages to sensor_stats index

    :param msg_list: a list of messages to save
    :type msg_list: list
    """
    now = datetime.now()
    bulk(
        es,
        _bulk_gendata(
            f"{index}-test_data-{str(now.year)}-{str(now.month)}-{str(now.day)}",
            msg_list,
        ),
    )


def _bulk_gendata(index, msg_list):
    for msg in msg_list:
        yield {"_op_type": "index", "_index": index, "_source": msg}


if __name__ == "__main__":
    main()
