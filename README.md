# [VirusTotal Private API] Maltego Local Transforms
Maltego Local Transforms to use VirusTotal Private API - https://www.virustotal.com/en/documentation/private-api/

# Prerequisites
- VirusTotal Private API access
- Python 2.7.x + requests, json, re module

# 必要なもの
- VirusTotal Private APIのアクセス権
- Python 2.7.x + requests, json, re モジュール

# Setup
- Edit VT.py and set "apikey" variable with your API key.  
- Put all python files into your working directory. (e.g. C:\Maltego\Transforms\VirusTotal)  
- Open VT.mtz to import Maltego configuration.  
- The current configuration uses the following directories, so you may have to change them according to your environment. (Maltego -> Transforms -> Transform Manager)  

  Command line = C:\Python27\python.exe  
  Working directory = C:\Maltego\Transforms\VirusTotal

# セットアップ
- VT.py の中で、\<Your API Key\> の箇所に自分の API key を記載してください。
- 全てのPythonファイルを、このTransform用に作ったディレクトリに置いてください。（例： C:\Maltego\Transforms\VirusTotal）
- VT.mtz を開いて、Maltegoの設定をインポートしてください。
- mtzファイルに含まれる設定では、下記のディレクトリが指定されていますが、自分の環境に合わせて変更してください。（Maltego -> Transforms -> Transform Manager）

  Command line = C:\Python27\python.exe  
  Working directory = C:\Maltego\Transforms\VirusTotal

# Transforms
- [VT] c2host_to_hash
- [VT] host_to_downloadedhash
- [VT] c2ip_to_hash
- [VT] ip_to_downloadedhash
- [VT] domain_to_ip
- [VT] ip_to_domain
- [VT] hash_to_c2host
- [VT] hash_to_c2ip
- [VT] hash_to_c2url
- [VT] hash_to_avdetection
- [VT] hash_to_filename
- [VT] hash_to_useragent
- [VT] hash_to_imphash
- [VT] hash_to_similar
- [VT] useragent_to_hash
- [VT] imphash_to_hash
- [VT] hash_to_rescan
- [VT] hash_to_section
- [VT] hash_to_timestamp
- [VT] hash_to_firstseen
- [VT] hash_to_filesize
- [VT] hash_to_filetype
- [VT] hash_to_peresource
- [VT] hash_to_itw
- [VT] hash_to_mutex
- [VT] hash_to_md5
- [VT] hash_to_sha256
- [VT] section_to_hash
- [VT] mutex_to_hash
- [VT] peresource_to_hash
- [VT] hash_to_detectratio
- [VT] url_to_detectratio
- [VT] domain_to_detectedurl
- [VT] ip_to_detectedurl
- [VT] domain_to_subdomain
- [VT] hash_to_import
- [VT] import_to_hash
- [VT] hash_to_tag
- [VT] hash_to_authentihash
- [VT] hash_to_pdb
- [VT] hash_to_behaviour / Beta
- [VT] behaviour_to_hash / Beta
