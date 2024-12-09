import argparse
import google.generativeai as genai
import os
from datetime import datetime

GOOGLE_API_KEY = ""

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-pro', safety_settings={
        'HARM_CATEGORY_DANGEROUS_CONTENT': 'BLOCK_ONLY_HIGH',
    })

VULNERABILITY_TYPES = [
    "SQLinjection",
    "OSCommandInjection",
    "PathTraversal",
    "CrossSiteScripting",
    "OpenRedirect",
    "HTTPHeaderInjection",
    "MailHeaderInjection",
    "LDAPInjection",
    "XPathInjection",
    "XXE",
    "SSIInjection",
    "XMLRPC",
    "CRLFInjection",
    "ParameterPollution",
    "SessionFixation",
    "CookieInjection",
    "CrossSiteRequestForgery",
    "Clickjacking",
    "InsecureDirectObjectReferences",
    "InsecureCryptographicStorage",
    "InsufficientTransportLayerProtection",
    "UnvalidatedRedirectsAndForwards",
    "MissingFunctionLevelAccessControl",
    "UsingComponentsWithKnownVulnerabilities",
    "SensitiveDataExposure",
    "SecurityMisconfiguration",
    "InsecureDeserialization",
    "InsufficientLoggingAndMonitoring",
    "UnrestrictedFileUpload",
    "BruteForce",
    "DenialOfService",
    "Other",
]

def classify_vulnerability(memo):
    # API に送信するプロンプト
    prompt = f"""
    From the following text, identify the single most relevant vulnerability type and output its name in English.

    Text: "{memo}"

    Possible vulnerability types:
    {VULNERABILITY_TYPES}

    Output:
    """
    try:
        response = model.generate_content(prompt)

        print("API Response:", response)

        if response.candidates:
            return response.candidates[0].content.parts[0].text.strip()
        elif response.promt_feedback:
            block_reason = response.prompt_feedback.block_reason
            print(f"Error: Prompt blocked due to : {block_reason}")
            if block_reason == "SAFETY":
                print("The prompt was blocked because it potentially violates the safety policy.")
            return None
        else:
            print("Error: No candidates found in response.")
            return None
    except Exception as e:
        print(f"Error during classification: {e}")
        return None

def generate_updated_content(filepath, memo, file_type):
    """
    既存のファイル内容と新しいメモを基に、Gemini APIを使用して更新されたファイル内容を生成する

    Args:
        filepath (str): 更新対象のファイルパス
        memo (str): 新しいメモの内容
        file_type (str): "Summary" または "Diagnosis"

    Returns:
        str: 更新されたファイル内容
    """
    try:
        with open(filepath, "r") as f:
            existing_content = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None
    
    # プロンプトのテンプレート
    if file_type == "Summary":
      prompt_template = f"""
You are an excellent security engineer.
Please add the new memo to the end of the "## Memo" section of the following Markdown file as a bullet point.
Follow the existing bullet point format in the file.

---
## Markdown file content:

{{existing_content}}

---
## New memo:

{{new_memo}}

---
## Instructions:

Update the "## Memo" section of the Markdown file content to include the new memo, and output the entire updated Markdown file content.
"""
    elif file_type == "Diagnosis":
      prompt_template = f"""
You are an excellent security engineer.
Please add the new memo to the end of the "## How to diagnose" section of the following Markdown file as a bullet point.
Follow the existing bullet point format in the file.

---
## Markdown file content:

{{existing_content}}

---
## New memo:

{{new_memo}}

---
## Instructions:

Update the "## How to diagnose" section of the Markdown file content to include the new memo, and output the entire updated Markdown file content.
"""

    prompt = prompt_template.format(existing_content=existing_content, new_memo=memo)

    try:
        response = model.generate_content(prompt)
        print(f"API Response in generate_updated_content: {response}")
        if response.candidates:
            return response.candidates[0].content.parts[0].text.strip()
        else:
            return None
    except Exception as e:
        print(f"Error generating updated content for {filepath}: {e}")
        return None
    

def append_to_file(filepath, memo, file_type):
    print(f"Entering append_to_file: filepath={filepath}, memo={memo}, file_type={file_type}")
    """
    Gemini APIを使用して、ファイルの内容を更新する

    Args:
        filepath (str): 更新対象のファイルパス
        memo (str): 新しいメモの内容
        file_type (str): "Summary" または "Diagnosis"
    """
    updated_content = generate_updated_content(filepath, memo, file_type)

    print(f"Updated content generated: {updated_content}")

    if updated_content:
        try:
            with open(filepath, "w") as f:
                f.write(updated_content)
            print(f"Updated {filepath}")
        except Exception as e:
            print(f"Error writing to {filepath}: {e}")
    else:
        print(f"Could not update {filepath}. Please check manually.")

def main():
    parser = argparse.ArgumentParser(description="Classify and append vulnerability memo.")
    parser.add_argument("memo", help="The vulnerability memo to process.")
    args = parser.parse_args()

    vault_path = os.getcwd()

    vulnerability_type = classify_vulnerability(args.memo)

    if vulnerability_type:
        print(f"Classified as: {vulnerability_type}")

        summary_path = os.path.join(vault_path, vulnerability_type, "Summary.md")
        diagnosis_path = os.path.join(vault_path, vulnerability_type, "Diagnosis.md")

        if not os.path.exists(summary_path):
            if input(f"'{vulnerability_type}/Summary.md' not found. Create it? (y/n): ").lower() == 'y':
              os.makedirs(os.path.dirname(summary_path), exist_ok=True) # ディレクトリが存在しない場合は作成
              open(summary_path, 'w').close()
            else:
                print("Skipping Summary.md")
        else:
            append_to_file(summary_path, args.memo, "Summary")

        if not os.path.exists(diagnosis_path):
            if input(f"'{vulnerability_type}/Diagnosis.md' not found. Create it? (y/n): ").lower() == 'y':
              os.makedirs(os.path.dirname(diagnosis_path), exist_ok=True)
              open(diagnosis_path, 'w').close()
            else:
                print("Skipping Diagnosis.md")
        else:
            append_to_file(diagnosis_path, args.memo, "Diagnosis")
    else:
        print("Could not classify vulnerability. Please classify manually.")

if __name__ == "__main__":
    main()
