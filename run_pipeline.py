# AndroByteTool/run_pipeline.py

import os
import argparse
import json
from parser.apk_parser import process_apk
from summarizer.llm_summarizer import main as summarizer_main


def load_settings(config_path):
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def run_pipeline(config_path, apk_name):
    settings = load_settings(config_path)

    apk_folder = settings.get("apk_folder", "APKFiles")
    output_base = settings.get("output_base", "outputs")
    apk_path = os.path.join(apk_folder, apk_name + ".apk")
    apk_output_folder = os.path.join(output_base, apk_name)

    #Extract bytecode instructions
    failed_apks = []
    empty_apks = []
    process_apk(apk_path, output_base, failed_apks, empty_apks)

    # Run summarization pipeline
    summarizer_main()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the full AndroByteTool pipeline.")
    parser.add_argument("--config", required=True, help="Path to the settings JSON file.")
    parser.add_argument("--apk_name", required=True, help="Name of the APK (without extension)")
    args = parser.parse_args()

    run_pipeline(args.config, args.apk_name)
