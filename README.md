# AndroByteTool: Android Privacy Analysis Framework

**AndroByteTool** is a static analysis tool designed to extract sensitive API call paths and summarize user data flow from Android APKs using bytecode-level analysis combined with LLM-based reasoning.

## Project Structure

AndroByteTool/
├── run_pipeline.py                   # Main entry point
├── parser/
│   └── apk_parser.py                # APK parsing and extracts bytecode instructions
├── summarizer/
│   ├── llm_summarizer.py             # summarization module + Ollama API + helper functions
│       
├── resources/
│   └── API.json                    # JSON list of sensitive API signatures
├── outputs/
│   └── <apk_name>/...                # Output per APK


Install via:
#bash
pip install -r requirements.txt


Ensure [Ollama](https://ollama.com/) is running locally and your model (e.g., `gemma3.1:latest`) is available.

---

## Usage
Run the tool from the command line:

#bash
python run_pipeline.py  --config configs/settings.json --apk_name <apk_filename_without_extension>


Optional arguments:
#bash
  --apk_folder        Path to folder containing APK files (default: ./APKFiles)
  --output_folder     Output base folder (default: ./outputs)
  --sensitive_api     Path to sensitive API JSON list (default: resources/API.json)


### Example:
#bash
python run_pipeline.py --config configs/settings.json  --apk_name my_app --apk_folder ./APKs --output_folder ./outputs

---

## Outputs
Each APK folder under `outputs/` will contain:

- `method_summaries.json` — summaries of each method 
- `refined_method_summaries.json` — summaries of each subgraph
- `sensitive_only.json` — subgraphs labeled as leak
- `visited_graph.png` — graph of analyzed paths
- `console_output.txt` — logs for debugging

---

## Notes
- The tool skips external libraries like `androidx`, `kotlin`, etc.
- Only methods with bytecode instructions and sensitive paths are included in the final graph.
- Supports large context windows via chunked instruction summarization.

---

## Contact
For issues or feature requests, please reach out to the tool maintainer or contribute via GitHub.
