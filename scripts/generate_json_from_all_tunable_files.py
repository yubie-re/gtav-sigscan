import json
import subprocess
import requests
import os
from datetime import datetime

EXE_DIR = "./sigscan.exe"
SAMPLE_DIR = "C:/Samples"


def load_json(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {'RTMA': [], 'INTG': []}


def save_json(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)


def create_signature_hash(signature):
    """Create a hash for a signature ignoring time and translation."""
    hashable_part = {key: val for key, val in signature.items() if key not in [
        'time', 'translation']}
    return json.dumps(hashable_part, sort_keys=True)


def merge_and_deduplicate(old_data, new_data):
    combined = {
        'RTMA': old_data.get('RTMA', []) + new_data.get('RTMA', []),
        'INTG': old_data.get('INTG', []) + new_data.get('INTG', [])
    }

    # Deduplicating data and keeping the oldest time
    for key in combined:
        unique = {}
        for sig in combined[key]:
            sig_hash = create_signature_hash(sig)
            if sig_hash in unique:
                # If this signature is already in unique, compare the time and keep the oldest
                if 'time' in sig and 'time' in unique[sig_hash]:
                    if sig['time'] < unique[sig_hash]['time']:
                        unique[sig_hash]['time'] = sig['time']
                # Ensure translation or other fields are also updated if necessary
                if 'translation' in sig and 'translation' not in unique[sig_hash]:
                    unique[sig_hash]['translation'] = sig['translation']
            else:
                # Otherwise, add the new signature to unique
                unique[sig_hash] = sig

        combined[key] = list(unique.values())

    return combined


def get_rdo_gg_tunable_list():
    resp = requests.get("https://api.rdo.gg/tunables/gta/pcros/all.json")
    return resp.json()


def get_rdo_gg_tunable_file(path):
    resp = requests.get("https://api.rdo.gg/" + path)
    return json.dumps(resp.json()["contents"])


if __name__ == "__main__":
    tunable_list = get_rdo_gg_tunable_list()
    for tunable_file in get_rdo_gg_tunable_list()["all"]:
        f = open("./tunables/" +
                 tunable_file["date"] + "%" + tunable_file["hash"] + ".json", 'wb')
        f.write(get_rdo_gg_tunable_file(tunable_file["url"]).encode('utf-8'))

    for subdir, dirs, files in os.walk('./tunables'):
        for file in files:
            file_path = os.path.join(subdir, file)
            file_name = file.split(".json")[0]
            date, tunable_hash = file_name.split("%")
            date_object = datetime.strptime(date, '%Y-%m-%d')
            timestamp = int(date_object.timestamp())
            print(date, tunable_hash, timestamp)
            print(subprocess.run([EXE_DIR, f"-t", file_path, f"--time", str(timestamp), "-s", "signatures.json",
                                  "-d", SAMPLE_DIR], capture_output=True))
            existing_sigs = load_json('sig_db.json')
            new_sigs = load_json('signatures.json')
            updated_sigs = merge_and_deduplicate(existing_sigs, new_sigs)
            save_json(updated_sigs, 'sig_db.json')
