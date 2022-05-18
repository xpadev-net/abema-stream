# [AbemaStream](https://xpadev.net/AbemaStream/)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/xpadev-net/niconicomments/blob/master/LICENSE)  
Abemaから生配信をダウンロードするコマンド兼モジュールです  
This is a script to download streams from Abema    
Github： https://github.com/xpadev-net/abema-stream  
PyPI： https://pypi.org/project/AbemaStream/

## ATTENTION
実行にはFFmpegが必要です

## Restriction
- 書き出しファイル名は配信のslot idに固定されています
- プレミアムには対応していません

## Installation
```
pip install AbemaStream
```

## Examples
```python
from AbemaStream import AbemaStream
AbemaStream("abema-anime", "/path/to/save/mp4")
```
```bash
python -m AbemaStream "abema-anime" "/path/to/save/mp4"
```

## External Source Code
以下の関数は外部のソースコードを引用しています
`_generate_applicationkeysecret`, `_get_videokey_from_ticket`  
Copyright (c) 2011-2016, Christopher Rosell  
Copyright (c) 2016-2022, Streamlink Team  
All rights reserved.  
Released under the BSD 2-Clause "Simplified" License  
License: https://github.com/streamlink/streamlink/blob/master/LICENSE  
source: https://github.com/streamlink/streamlink/blob/master/src/streamlink/plugins/abematv.py  