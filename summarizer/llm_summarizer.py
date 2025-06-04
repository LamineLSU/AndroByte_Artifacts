import os
import json
import requests
import time
import re
import logging
import sys
import json_repair
import io
from collections import deque
import networkx as nx
from graphviz import Digraph

GLOBAL_MODEL ="gemma3:latest"
#GLOBAL_MODEL = "llama3.1:latest"
#GLOBAL_MODEL = "deepseek-r1:7b"
#GLOBAL_MODEL ="qwen3:latest"
#GLOBAL_MODEL = "deepseek-coder-v2:16b"

MAX_TOKENS = 40000

# Updated Tee class to write to multiple outputs and avoid flushing closed files
class Tee: 
    def __init__(self, *files):
        self.files = files

    def write(self, data):
        for f in self.files:
            try:
                f.write(data)
            except Exception as e:
               
                pass

    def flush(self):
        for f in self.files:
            if not f.closed:
                try:
                    f.flush()
                except Exception:
                    pass

# OLLAMA API CALL
def ollama_chat(prompt, model=GLOBAL_MODEL, num_ctx=MAX_TOKENS, max_retries=3):
    url = "http://localhost:11434/api/chat"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": "json_object",
        "stream": False,
        "options": {"num_ctx": num_ctx, "temperature": 0.4}
    }
    retries = 0
    while retries < max_retries:
        try:
            response = requests.post(url, json=payload, timeout=300)
            response.raise_for_status()
            response_json = response.json()
            return response_json.get("message", {}).get("content", "")
        except Exception as e:
            print(f"Error in API call: {e}")
            retries += 1
            time.sleep(2)
    raise Exception("Maximum retries exceeded for Ollama API call.")

def extract_valid_json(response):
    """
    Attempt to extract valid JSON from the response by:
      1) Removing known extraneous lines like 'Here is the output...' etc.
      2) Finding the FIRST '{' and the LAST '}' in the string.
      3) Parsing the substring between them as JSON.
    """
    try:
        # Remove code fences
        response = re.sub(r'```json\s*', '', response, flags=re.IGNORECASE)
        response = re.sub(r'```', '', response)
        patterns_to_remove = [
            r'Here\s?is\s?the\s?output.*?\n?',
            r'Here\s?is\s?the\s?integrated\s?summary.*?\n?',
            r'Please\s?note.*?\n?',
            r'Output\s?\n?:.*?\n?',
        ]
        for pat in patterns_to_remove:
            response = re.sub(pat, '', response, flags=re.IGNORECASE)

        # Find the first '{' and the last '}'
        start_idx = response.find('{')
        end_idx = response.rfind('}')
        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            raise ValueError("No valid JSON block found in the response.")
        json_str = response[start_idx:end_idx+1].strip()

        return json.loads(json_str)

    except (ValueError, json.JSONDecodeError) as e:
        logging.error(f"Error extracting JSON: {e}")
        logging.error(f"Response received:\n{response}\n")
        return {}


def normalize_method_signature(signature):
    """
    Normalize a method signature by removing spaces, colons, quotes, brackets,
    and ensuring consistent casing.
    """
    signature = (signature
                 .replace(" ", "")
                 .replace(":", "")
                 .replace("\n", "")
                 .replace('"', "")
                 .replace("[", "")
                 .replace("]", "")
                 .lower()).rstrip(";")
    return signature

def load_json_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_sensitive_calls(method, sensitive_apis):
    """
    Returns a list of {"caller": <full signature>, "callee": <API>} if the
    method's instructions contain a sensitive API call.
    """
    sensitive_calls = []
    caller_sig = method.get("method_signature", "")
    instructions = " ".join(method.get("instructions", []))
    norm_instructions = normalize_method_signature(instructions)
    for api in sensitive_apis:
        norm_api = normalize_method_signature(api)
        if norm_api in norm_instructions:
            sensitive_calls.append({"caller": caller_sig, "callee": api})
    return sensitive_calls

def summarize_instructions_in_chunks(instructions_text, chunk_size=300):
    lines = instructions_text.splitlines()
    if len(lines) <= chunk_size:
        return instructions_text

    partial_jsons = []
    for i in range(0, len(lines), chunk_size):
        chunk = "\n".join(lines[i:i + chunk_size])

        partial_prompt = (
            f"You are an expert in analyzing Android bytecode instructions. Your task is to identify how user personal data is originated, "
            f"propagated through registers, and passed between methods, ultimately reaching sinks such as data logging, transmission, or display.\n\n"
            f"### Instructions:\n"
            f"1. **Data Origin Identification**: Determine if the current method is using sensitive api call to originates any sensitive user personal data.\n"
            f"2. **Data Storage Analysis**: Analyze how the data is stored in registers or variables within the method.\n"
            f"3. **Data Propagation Analysis**: Trace how the data is passed to other methods via method invocations.\n"
            f"4. **Sink Identification**: Identify if and how the data reaches any **sink points like logging, network transmission, or storage.\n"
            f"5. **Next Methods to Analyze**: List the method signatures from bytecode instructions analysis that should be analyzed next based on the data flow.\n\n"
            f"### Additional Strict Rule for Next Methods Selection: \n"
            f" **Exclude any methods that belong to external or framework libraries. Specifically, do not include methods from:\n"
            f" **`Landroid/*` \n"
            f" **`Landroidx/*` \n"
            f" **`Lkotlin/*` \n"
            f" **Do not guess or infer `Next Methods` not in the input bytecode instructions.\n"
            f" **The `Next Methods` field must list only those methods directly invoked in the current method's instructions. If no methods are invoked or if no applicable methods match the criteria, `Next Methods` must be `[]`.\n"
            f"### Output Format:\n"
            f"Provide your analysis strictly in the following JSON format **without any additional text**:\n\n"
            f"```json\n"
            f"{{\n"
            f"    \"Summary\": \"[Summary of data origin, storage, propagation, and sinks within this method]\",\n"
            f"    \"Next Methods\": [\n"
            f"        \"Lfully/qualified/ClassName;->methodName:(parameter_type_1;parameter_type_2;...parameter_type_n)return_type\"\n"
            f"    ]\n"
            f"}}\n"
            f"```\n\n"
            f"### Method Signature Format:\n"
            f"`Lfully/qualified/ClassName;->methodName:(parameter_types)return_type;`\n"
            f"### Rules:\n"
            f"1. **No Additional Text**: Return only JSON.\n"
            f"2. **Exact Format**.\n"
            f"3. **Complete Signatures**.\n"
            f"4. **Consistent Casing**.\n"
            f"5. **No Truncated Signatures**.\n"
            f"6. **Only Invoked Methods**.\n"
            f"7. **If sink identified =>** `Next Methods = []`.\n"
            f"8. **If no sensitive API =>** Summarize.\n"
            f"9. **Don't include any example from the prompt**.\n"
            f"10. **A normal return statement is not considered a sink**. Only explicit calls to logging, network, or data storage are sinks.\n\n"
            f"CHUNK: {chunk}\n"
        )

        try:
            partial_response_str = ollama_chat(partial_prompt).strip()
            parsed_json = extract_valid_json(partial_response_str)
            if parsed_json:
                partial_jsons.append(parsed_json)
            else:
                partial_jsons.append({
                    "Summary": "No valid JSON returned for this chunk.",
                    "Next Methods": []
                })
        except Exception as e:
            print(f"Error while summarizing chunk: {e}")
            partial_jsons.append({
                "Summary": f"Error: {e}",
                "Next Methods": []
            })

    return json.dumps(partial_jsons, indent=4)




def create_prompt(method, previous_summary="No previous summary available."):
    """
    Constructs the LLM prompt using the method's instructions and full signature.
    """
    #instructions_text = "\n".join(method.get("instructions", []))
    instructions_text = summarize_instructions_in_chunks("\n".join(method.get("instructions", [])), chunk_size=300)
    prompt = (
        f"You are an expert in analyzing Android bytecode instructions. Your task is to identify how user personal data is originated, "
        f"propagated through registers, and passed between methods, ultimately reaching sinks such as data logging, transmission, or display.\n\n"
        f"### Instructions:\n"
        f"1. **Data Origin Identification**: Determine if the current method is using sensitive api call to originates any sensitive user personal data.\n"
        f"2. **Data Storage Analysis**: Analyze how the data is stored in registers or variables within the method.\n"
        f"3. **Data Propagation Analysis**: Trace how the data is passed to other methods via method invocations.\n"
        f"4. **Next Methods to Analyze**: List the method signatures from bytecode instructions analysis that should be analyzed next based on the data flow.\n\n"
        f"5. **Sink Identification**: Identify if and how the data reaches any **sink points like logging, network transmission, or storage.\n"
        f"### Additional Strict Rule for Next Methods Selection: \n"
        f" **Exclude any methods that belong to external or framework libraries. Specifically, do not include methods from:\n"
        f" **`Landroid/*` \n"
        f" **`Landroidx/*` \n"
        f" **`Lkotlin/*` \n"
        f" **Do not guess or infer `Next Methods` not in the input bytecode instructions.\n"
        f" **The `Next Methods` field must list only those methods directly invoked in the current method's instructions. If no methods are invoked or if no applicable methods match the criteria, `Next Methods` must be `[]`.\n"
        f"### Output Format:\n"
        f"Provide your analysis strictly in the following JSON format **without any additional text**:\n\n"
        f"```json\n"
        f"{{\n"
        f"    \"Summary\": \"[Summary of data origin, storage, propagation, and sinks within this method]\",\n"
        f"    \"Next Methods\": [\n"
        f"        \"Lfully/qualified/ClassName;->methodName:(parameter_type_1;parameter_type_2;...parameter_type_n)return_type\"\n"
        f"    ]\n"
        f"}}\n"
        f"```\n\n"
        f"### Method Signature Format:\n"
        f"`Lfully/qualified/ClassName;->methodName:(parameter_types)return_type;`\n"
        f"### Rules:\n"
        f"1. **No Additional Text**: Return only JSON object.\n"
        f"2. **Exact Format**.\n"
        f"3. **Complete Signatures**.\n"
        f"4. **Consistent Casing**.\n"
        f"5. **No Truncated Signatures**.\n"
        f"6. **Only Invoked Methods**.\n"
        f"7. **If sink identified =>** `Next Methods = []`.\n"
        f"8. **If no sensitive API =>** Summarize.\n"
        f"9. **Don't include any example from the prompt**.\n"
        f"10. **A normal return statement is not considered a sink**. Only explicit calls to logging, network, or data storage are sinks.\n\n"
        f"### Previous Summary:\n{previous_summary}\n\n"
        f"### Current Method Signature:\n" + method.get('method_signature', '') + "\n\n"
        f"### Instructions:\n" + instructions_text + "\n\n"
    )
    return prompt


def sanitize_dot_id(text):
    """
    Replaces special characters that confuse Graphviz (like (, ), :, ;, /, etc.)
    with underscores so the node ID is safe.
    """
    return re.sub(r'[^a-zA-Z0-9_]+', '_', text)

def generate_graph_png(graph, output_filename="Model_visited_graph.png", dpi = 300):
    """
    Generates a PNG of the visited graph using Graphviz.
    Uses a sanitized version of the signature as the node ID,
    and uses the full signature as the label.
    """
    dot = Digraph(comment="Visited Subgraph", format="png")
    dot.graph_attr.update({
        'dpi': str(dpi)
    })
    # Create all nodes
    for node in graph.nodes():
        full_signature = graph.nodes[node].get("label", node)
        node_id = sanitize_dot_id(full_signature)
        dot.node(node_id, label=full_signature)
    # Create edges
    for src, dst in graph.edges():
        src_label = graph.nodes[src].get("label", src)
        dst_label = graph.nodes[dst].get("label", dst)
        src_id = sanitize_dot_id(src_label)
        dst_id = sanitize_dot_id(dst_label)
        dot.edge(src_id, dst_id)
    dot.render(filename=output_filename, cleanup=True)
    print(f"Graph exported to {output_filename}")



def refine_single_subgraph_summary(subgraph_dict):
    """
    Summarize a single subgraph's {method_signature -> summary} in one LLM call,
    taking overwriting into account to decide if a sink is truly receiving tainted data.
    """
    # Convert subgraph summaries into a list for JSON
    methods_data = []
    for sig, summ in subgraph_dict.items():
        methods_data.append({
            "Method Signature": sig,
            "Summary": summ
        })
    methods_json_str = json.dumps(methods_data, indent=4)
    
    prompt = (
        f"You are analyzing a set of final method-level summaries that describe how data flows across methods in one subgraph. "
        f"Each item may show sources (e.g., getDeviceId), overwriting operations, and potential sink calls.\n\n"
        
        f"### Given Data:\n"
        f"```json\n{methods_json_str}\n```\n\n"
        
        f"### Overwrite & Taint Loss Rule\n"
        f"- If a method summary shows that a sensitive value (like `DeviceId`) was overwritten with a safe constant (e.g., `abc`), that data is no longer tainted.\n"
        f"- Therefore, if a sink method uses that overwritten value, it's **not** a leak.\n\n"
        
        f"### Sink Argument Rule\n"
        f"- Only include a sink in `All Sinks` if the **exact** argument passed at call time is still tainted from a sensitive source.\n"
        f"- If the argument was overwritten with a non-sensitive value (e.g., a constant string) or if the summary explicitly states that the taint was removed, do **not** list that sink.\n\n"
        f"###RULES (You must follow them strictly)\n"
        f"1. The output must be a single valid JSON object enclosed in '{' and '}'.\n"
        f"2. No markdown formatting, no '```' fences, and no Python code examples. \n"
        f"3. No explanations or text outside the JSON.\n"
        f"4.Output must be valid #JSON object, with no additional text, with no markdown, no code fences, and no additional explanations.\n"
        
        f"### Final Output Format\n"
        f"Return exactly one JSON object,like this (with your actual data and fields):\n"
        f"```json\n"
        f"{{\n"
        f"    \"Data Types Collected\": [\n"
        f"        \"...\"\n"
        f"    ],\n"
        f"    \"Overall Data Flow\": [\n"
        f"        {{\n"
        f"            \"Step\": \"[Short description]\",\n"
        f"            \"Source Method\": \"[Full method signature]\",\n"
        f"            \"Reasoning\": \"[Reasoning]\",\n"
        f"            \"Action\": \"[Stored, logged, transmitted, etc.]\"\n"
        f"        }}\n"
        f"    ],\n"
        f"    \"All Sinks\": [\n"
        f"        \"[Full method signature of sink method or null]\"\n"
        f"    ],\n"
        f"    \"Complete Data Flow\" : [\n"
        f"      {{\n"
        f"          \"dataflow 1\": \" [complete Source Method(...) --> ... --> Sink Method(...)]\",\n"
        f"          \"Reasoning\": \"[Stepwise explanation of how data is propagated and transformed]\"\n"
        f"      }}\n"
        f"    ],\n"
        f"     \"Label\" :[\n"
        f"          \" leak or no leak \"\n"
        f"      ]\n"
        f"}}\n"
        f"```\n\n"
        f"Remember:\n"
        f"- No extra text or code. \n"
        f"- No lines like 'Here is a Python solution...'.\n"
        f"### Strict Instructions\n"
        f"1. If **any** method final state shows an un-overwritten (still tainted) source is passed to a sink, set `Label` to `leak`.\n"
        f"2. Otherwise, if everything is overwritten or not actually passed to a sink, set `All Sinks` to `null`, `Complete Data Flow` to `null`, and `Label` to `no leak`.\n"
        f"3. If no data is collected at all, set `Data Types Collected` to `null`.\n"
        f"4. Do not guess or assume. Only rely on the method summaries above.\n\n"
    )
    
    response = ollama_chat(prompt)  
  
    refined_json = extract_valid_json(response)
    

    if refined_json:
        all_sinks = refined_json.get("All Sinks")
        if not all_sinks or all_sinks in ([], [None], None):
            refined_json["All Sinks"] = None
            #refined_json["Complete Data Flow"] = None
            refined_json["Label"] = "no leak"
    return refined_json


def refine_all_subgraphs_separately(all_subgraphs):
    """
    Instead of merging subgraph summaries, produce one refined JSON per subgraph 
    and collect them in a list.
    """
    refined_results = []
    for idx, subgraph_dict in enumerate(all_subgraphs, start=1):
        logging.info(f"\nRefining Subgraph #{idx}:")
        refined_json = refine_single_subgraph_summary(subgraph_dict)
        refined_results.append(refined_json)
    return refined_results


def chunk_list(data_list, chunk_size):
    for i in range(0, len(data_list), chunk_size):
        yield data_list[i : i + chunk_size]


def refine_final_summary_for_chunk(chunk_dict, max_retries=3):
    methods_data = []
    for method_sig, summary in chunk_dict.items():
        methods_data.append({"Method Signature": method_sig, "Summary": summary})
    methods_json_str = json.dumps(methods_data, indent=4)

    prompt = (
        f"You are an expert in analyzing Android bytecode instructions and sensitive data flows. (e.g., location, device ID, phone number). Do not include generic data types.\n"
        f"You have multiple final summaries for different methods, and you need to produce a single integrated summary to identify sensitive dataflow.\n\n"
        f"### Given Data:\n"
        f"```json\n{methods_json_str}\n```\n\n"
        f"### Your Task:\n"
        f"1.  Identify all unique **user personal data types** collected across all methods (e.g., location, device ID, phone number). Do not include generic data types.\n"
        f"2. Combine **only** sensitive data flows from these user **personal sensitive data types** collected source methods into a single, coherent representation under \"Overall Data Flow\".\n"
        f"3. Identify all sink points(logging, network calls, or file writes, etc.) using full method signatures in \"All Sinks\".\n\n"
        f"4. Explain exactly **how** personal data ends up in each sink, listing **complete** stepwise flows. Each flow can span multiple methods (e.g., Method A --> Method B --> Method C). Use **\"Complete Data Flow\"** for this.\n"
        f"5. Provide a `Label` field at the root level, set to \"sensitive\" if any personal data sink point is identified, otherwise \"not_sensitive\".\n\n"
        f"### Output Format:\n"
        f"```json\n"
        f"{{\n"
        f"    \"Data Types Collected\": [\n"
        f"        \"...\"\n"
        f"    ],\n"
        f"    \"Overall Data Flow\": [\n"
        f"        {{\n"
        f"            \"Step\": \"[Short description]\",\n"
        f"            \"Source Method\": \"[Full method signature]\",\n"
        f"            \"Reasoning\": \"[Reasoning]\",\n"
        f"            \"Action\": \"[Stored, logged, transmitted, etc.]\",\n"
        f"        }}\n"
        f"    ]\n"
        f"    \"All Sinks\": [\n"
        f"        \"[Full method signature of sink method]\"\n"
        f"    ]\n"
        f" \"Complete Data Flow\" : [\n"
        f"      {{\n"
        f"          \"dataflow 1\": \" [Source Method(collected user data) --> intermediary Methods -->AnotherIntermediate(...) --> Sink Method(Data is logged,displayed,transmitted over the network)]\"\n"
        f"            \"Reasoning\": \"[Stepwise explanation of how data is propagated and transformed]\"\n"
        f"       }}\n"
        f"  ],\n"
        f"     \"Label\" :[\n"
        f"          \" leak or no leak \"\n"
        f"      ]\n"
        f"}}\n"
        f"```\n\n"
        f"### Rules:\n"
        f"1. **No Additional Text**: Provide only valid JSON, nothing else.\n"
        f"2. **Enumerate All sensitive Data Flow**: Do not omit any.\n"
        f"3. **Single JSON Object** only.\n"
        f"4. **Do Not Include Examples**.\n"
        f"5. **Use the Provided Summaries**.\n"
        f"6. **No Ellipses**.\n"
        f"7. **If no sink or no data flow** is found, set that field to `null` instead of an empty array.\n"
        f"8. **If no sink or no sensitive data flow is found, set Complete Data Flow as `null` \n"
        f"9. **If no sinks exist for personal data, the final `Label` must be `no leak`.\n"
    )

    for attempt in range(max_retries):
        response = ollama_chat(prompt)
        result = extract_valid_json(response)
        if result:
            return result
    return {
        "Data Types Collected": [],
        "Overall Data Flow": [],
        "All Sinks": [],
        "Complete Data Flow": None,
        "Label": "no leak"
    }


def merge_partial_final_summaries(partial_summaries):
    aggregated_data_types = set()
    aggregated_data_flow = []
    aggregated_sinks = set()

    for summary in partial_summaries:
        for dt in summary.get("Data Types Collected", []):
            aggregated_data_types.add(dt)
        for flow_step in summary.get("Overall Data Flow", []):
            aggregated_data_flow.append(flow_step)
        for sink in summary.get("All Sinks", []):
            aggregated_sinks.add(sink)

    return {
        "Data Types Collected": list(aggregated_data_types),
        "Overall Data Flow": aggregated_data_flow,
        "All Sinks": list(aggregated_sinks)
    }


def refine_final_summary_in_chunks(all_summaries, chunk_size=3):
    items = list(all_summaries.items())
    partial_results = []
    for chunk in chunk_list(items, chunk_size):
        chunk_dict = dict(chunk)
        partial_json = refine_final_summary_for_chunk(chunk_dict)
        partial_results.append(partial_json)
    merged_result = merge_partial_final_summaries(partial_results)
    return merged_result


def integrate_chunked_summary_from_main(global_summaries):
    print("\n[Chunk-Based Summary Integration: Starting final summary chunk refinement...]")
    merged_summary = refine_final_summary_in_chunks(global_summaries, chunk_size=3)
    print("\n[Chunk-Based Summary Result (Merged)]:")
    print(json.dumps(merged_summary, indent=4))
    return merged_summary

def main():
    start_time = time.time()
    

    MASTER_FOLDER = r"D:\UBCBAPK_Methods"
    sensitive_api_path = r"api_path"
    
    for subfolder in os.listdir(MASTER_FOLDER):
        subfolder_path = os.path.join(MASTER_FOLDER, subfolder)
        if not os.path.isdir(subfolder_path):
            continue
        
        json_files = [f for f in os.listdir(subfolder_path) if f.endswith('_bytecode_instructions.json')]
        if not json_files:
            print(f"No bytecode instructions JSON file found in {subfolder_path}")
            continue
        
     
        methods_json_path = os.path.join(subfolder_path, json_files[0])
        output_dir = os.path.join(subfolder_path, "output")
        os.makedirs(output_dir, exist_ok=True)

        output_graph_path = os.path.join(output_dir, "visited_graph")
        output_summaries_path = os.path.join(output_dir, "method_summaries.json")
        output_refined_summaries_path = os.path.join(output_dir, "refined_method_summaries.json")
        output_sensitive_mapping = os.path.join(output_dir, "sensitive_calls.json")
        console_output_file = os.path.join(output_dir, "console_output.txt")

        old_stdout = sys.stdout
        with open(console_output_file, 'w', encoding='utf-8') as console_file:
            sys.stdout = Tee(sys.__stdout__, console_file)
            
            print(f"Processing folder: {subfolder_path}")
            print(f"Using methods file: {methods_json_path}")
            
            # Load JSON data
            methods_data = load_json_file(methods_json_path)
            sensitive_api_data = load_json_file(sensitive_api_path)
            sensitive_apis = sensitive_api_data.get("sensitive_apis", [])
            
            #  lookup dict using the complete signature as the key
            method_lookup = {}
            for _, method_info in methods_data.items():
                full_sig = method_info.get("method_signature", "")
                norm_sig = normalize_method_signature(full_sig)
                method_lookup[norm_sig] = (full_sig, method_info)
            
            # Global traversal data
            global_visited = set()           
            global_summaries = {}            
            global_next_methods = {}         
            global_graph = nx.DiGraph()
            sensitive_call_mapping = []
            subgraph_summaries = []          
            
            # Identify root methods
            sensitive_roots = []
            for _, method_info in methods_data.items():
                calls = get_sensitive_calls(method_info, sensitive_apis)
                if calls:
                    full_sig = method_info.get("method_signature", "")
                    print(f"Sensitive method found: {full_sig}")
                    sensitive_call_mapping.extend(calls)
                    sensitive_roots.append(full_sig)
            
            if not sensitive_roots:
                print("No sensitive methods detected based on the provided API list.")
            
            # DFS traversal 
            for root_sig in sensitive_roots:
                if root_sig in global_visited:
                    continue
                local_stack = deque()
                local_stack.append({"current": root_sig, "parent": None, "root": root_sig})
                global_visited.add(root_sig)
                
                local_subgraph_summary = {}
                
                norm_root_sig = normalize_method_signature(root_sig)
                if norm_root_sig in method_lookup:
                    _, root_method_info = method_lookup[norm_root_sig]
                    global_graph.add_node(root_sig, label=root_method_info.get("method_signature", root_sig))
                
                while local_stack:
                    item = local_stack.pop()
                    current_sig = item["current"]
                    parent_sig = item["parent"]
                    root_sig_ = item["root"]
                    
                    norm_current_sig = normalize_method_signature(current_sig)
                    if norm_current_sig not in method_lookup:
                        continue
                    _, current_method_info = method_lookup[norm_current_sig]
                    
                    if current_sig not in global_summaries:
                        prev_summary = global_summaries.get(parent_sig, "No previous summary available.") if parent_sig else "No previous summary available."
                        prompt = create_prompt(current_method_info, previous_summary=prev_summary)
                        try:
                            response = ollama_chat(prompt)
                            parsed = extract_valid_json(response)
                        except Exception as e:
                            print(f"Error processing method {current_sig}: {e}")
                            continue
                        summary_text = parsed.get("Summary", "No summary provided.")
                        next_methods = parsed.get("Next Methods", [])
                        global_summaries[current_sig] = summary_text
                        global_next_methods[current_sig] = next_methods
                        local_subgraph_summary[current_sig] = summary_text
                        print(f"Processed summary for {current_sig}: {json.dumps(parsed, indent=4)}")
                    else:
                        next_methods = global_next_methods.get(current_sig, [])
                    
                    if parent_sig:
                        global_graph.add_edge(parent_sig, current_sig)
                    
                    for nm in next_methods:
                        norm_nm = normalize_method_signature(nm)
                        if norm_nm in method_lookup:
                            next_full_sig, next_method_data = method_lookup[norm_nm]
                            if next_full_sig not in global_visited:
                                global_visited.add(next_full_sig)
                                local_stack.append({"current": next_full_sig, "parent": current_sig, "root": root_sig_})
                                global_graph.add_node(next_full_sig, label=next_method_data.get("method_signature", next_full_sig))
                                global_graph.add_edge(current_sig, next_full_sig)
            
                subgraph_summaries.append(local_subgraph_summary)
            
            with open(output_summaries_path, 'w', encoding='utf-8') as f:
                json.dump(subgraph_summaries, f, indent=4)
            print(f"Method summaries saved to {output_summaries_path}")
            
            with open(output_sensitive_mapping, 'w', encoding='utf-8') as f:
                json.dump(sensitive_call_mapping, f, indent=4)
            print(f"Sensitive call mapping saved to {output_sensitive_mapping}")
            
            generate_graph_png(global_graph, output_filename=output_graph_path)
            
            refined_subgraph_summaries = refine_all_subgraphs_separately(subgraph_summaries)
            
            print("Refined Subgraph Summaries:")
            print(json.dumps(refined_subgraph_summaries, indent=4))
            
            with open(output_refined_summaries_path, 'w', encoding='utf-8') as f:
                json.dump(refined_subgraph_summaries, f, indent=4)
            print(f"Refined method summaries saved to {output_refined_summaries_path}")

           
            sensitive_only = []
            for subgraph_result in refined_subgraph_summaries:
                label_value = subgraph_result.get("Label", "")
                if isinstance(label_value, str):
                   # if label_value.strip().lower() == "sensitive":
                   if label_value.strip().lower() == "leak":
                        sensitive_only.append(subgraph_result)
                elif isinstance(label_value, list):
                    for label in label_value:
                        #if label.strip().lower() == "sensitive":
                        if label.strip().lower() == "leak":
                            sensitive_only.append(subgraph_result)
                            break

          
            sensitive_file_path = os.path.join(output_dir, "sensitive_only.json")
            with open(sensitive_file_path, "w", encoding="utf-8") as sf:
                json.dump(sensitive_only, sf, indent=4)
            print(f"Saved {len(sensitive_only)} 'sensitive' subgraphs to: {sensitive_file_path}")
         
            
            total_time = time.time() - start_time
            print(f"Total summary time: {total_time} seconds")
            
            
        sys.stdout = old_stdout
        print(f"Finished processing folder: {subfolder_path}\n")
    
    print("All folders have been processed.")

if __name__ == "__main__":
    main()
