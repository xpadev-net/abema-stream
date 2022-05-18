import copy
import hashlib
import hmac
import json
import logging
import os.path
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid
import sys
from base64 import urlsafe_b64encode
from binascii import unhexlify

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

logging.basicConfig(
    level=logging.DEBUG, format='%(asctime)s %(threadName)s: %(message)s')
logger = logging.getLogger()

channel_list = [
    "abema-news", "news-plus", "abema-special", "special-plus", "special-plus-2", "drama", "drama-2", "asia-drama",
    "asia-drama-2", "k-world", "abema-anime", "abema-anime-2", "abema-anime-3", "anime-live", "anime-live2",
    "anime-live3", "everybody-anime", "everybody-anime2", "everybody-anime3", "commercial", "hiphop", "abema-radio",
    "fighting-sports", "fighting-sports2", "fighting-sports3", "fighting-sports4", "world-sports", "world-sports-1",
    "world-sports-2", "world-sports-3", "world-sports-4", "world-sports-5", "boatrace", "keirin-auto", "fishing",
    "shogi", "shogi-live", "mahjong", "mahjong-live", "sumo", "world-tennis", "world-tennis02", "metrock",
    "test-broadcast", "news-global", "payperview-pr", "payperview-pr-2"
]
log_levels = {
    "CRITICAL": 50,
    "ERROR": 40,
    "WARNING": 30,
    "INFO": 20,
    "DEBUG": 10,
    "NOTSET": 0
}


class AbemaStream:
    SECRETKEY = (b"v+Gjs=25Aw5erR!J8ZuvRrCx*rGswhB&qdHd_SYerEWdU&a?3DzN9B"
                 b"Rbp5KwY4hEmcj5#fykMjJ=AuWz5GSMY-d@H7DMEh3M@9n2G552Us$$"
                 b"k9cD=3TxwWe86!x#Zyhe")
    STRTABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    HKEY = b"3AF0298C219469522A313570E8583005A642E73EDD58E3EA2FB7339D3DF1597E"

    def __init__(self, channel, output_dir, temp_dir=None, target=None, log_level=None):
        if channel not in channel_list:
            logger.error("Unknown channel")
            sys.exit(1)
        if not os.access(output_dir, os.W_OK):
            logger.error("Cannot write to output folder")
            sys.exit(1)
        if log_level and log_level in log_levels:
            logger.setLevel(log_levels[log_level])
        else:
            logger.setLevel(0)
        self.downloading = False
        self.user_token = None
        self.device_id = None
        self.app_key_secret = None
        self.iv = None
        self.url = "https://ds-linear-abematv.akamaized.net/channel/{}/1080/playlist.m3u8".format(channel)
        self.segments = []
        self.urls = []
        self.downloaded_filename = []
        self.key = b""
        self.key_raw = None
        self.channel = channel
        self.slot = None
        self.output_dir = output_dir
        self.downloaded_slot = ""
        self.ignore = False
        self.gen_session()
        self.target = target

        with tempfile.TemporaryDirectory(dir=temp_dir, prefix="abema-stream_") as dname:
            self.tmpdir = dname
            stream = threading.Thread(target=self.read)
            download = threading.Thread(target=self.download)
            stream.start()
            logger.debug("stream: start")
            download.start()
            logger.debug("download: start")
            download.join()

    def gen_session(self):
        self.device_id = str(uuid.uuid4())
        self.app_key_secret = self._generate_applicationkeysecret(self.device_id)
        json_data = {"deviceId": self.device_id,
                     "applicationKeySecret": self.app_key_secret}
        req = urllib.request.Request("https://api.abema.io/v1/users",
                                     headers={'Content-Type': 'application/json'},
                                     data=json.dumps(json_data).encode('utf-8'))
        with urllib.request.urlopen(req) as res:
            self.user_token = json.loads(res.read())["token"]
            logger.debug("token: {}".format(self.user_token))

    def _generate_applicationkeysecret(self, device_id):
        device_id = device_id.encode("utf-8")
        ts_1hour = (int(time.time()) + 60 * 60) // 3600 * 3600
        time_struct = time.gmtime(ts_1hour)
        ts_1hour_str = str(ts_1hour).encode("utf-8")

        h = hmac.new(self.SECRETKEY, digestmod=hashlib.sha256)
        h.update(self.SECRETKEY)
        tmp = h.digest()
        for i in range(time_struct.tm_mon):
            h = hmac.new(self.SECRETKEY, digestmod=hashlib.sha256)
            h.update(tmp)
            tmp = h.digest()
        h = hmac.new(self.SECRETKEY, digestmod=hashlib.sha256)
        h.update(urlsafe_b64encode(tmp).rstrip(b"=") + device_id)
        tmp = h.digest()
        for i in range(time_struct.tm_mday % 5):
            h = hmac.new(self.SECRETKEY, digestmod=hashlib.sha256)
            h.update(tmp)
            tmp = h.digest()

        h = hmac.new(self.SECRETKEY, digestmod=hashlib.sha256)
        h.update(urlsafe_b64encode(tmp).rstrip(b"=") + ts_1hour_str)
        tmp = h.digest()

        for i in range(time_struct.tm_hour % 5):  # utc hour
            h = hmac.new(self.SECRETKEY, digestmod=hashlib.sha256)
            h.update(tmp)
            tmp = h.digest()

        return urlsafe_b64encode(tmp).rstrip(b"=").decode("utf-8")

    def _get_videokey_from_ticket(self, ticket):
        params = {
            "osName": "android",
            "osVersion": "6.0.1",
            "osLang": "ja_JP",
            "osTimezone": "Asia/Tokyo",
            "appId": "tv.abema",
            "appVersion": "3.27.1"
        }
        req = urllib.request.Request("https://api.abema.io/v1/media/token?{}".format(urllib.parse.urlencode(params)),
                                     headers={"Authorization": "Bearer " + self.user_token})
        with urllib.request.urlopen(req) as res:
            self.media_token = json.loads(res.read())['token']
        req = urllib.request.Request(
            "https://license.abema.io/abematv-hls?{}".format(urllib.parse.urlencode({"t": self.media_token})),
            headers={"Authorization": "Bearer " + self.user_token},
            data=json.dumps({"kv": "a", "lt": ticket}).encode('utf-8'), method='POST')
        with urllib.request.urlopen(req) as res:
            jsonres = json.loads(res.read())
            cid = jsonres['cid']
            k = jsonres['k']

        res = sum([self.STRTABLE.find(k[i]) * (58 ** (len(k) - 1 - i))
                   for i in range(len(k))])
        encvideokey = struct.pack('>QQ', res >> 64, res & 0xffffffffffffffff)

        h = hmac.new(unhexlify(self.HKEY),
                     (cid + self.device_id).encode("utf-8"),
                     digestmod=hashlib.sha256)
        enckey = h.digest()

        aes = AES.new(enckey, AES.MODE_ECB)
        rawvideokey = aes.decrypt(encvideokey)
        return rawvideokey

    def read(self):
        while True:
            lastline = ""
            try:
                req = urllib.request.Request(self.url)
                with urllib.request.urlopen(req) as res:
                    lines = res.read().decode("utf-8").strip().split("\n")
                    for item in lines:
                        key = re.match(r"^#EXT-X-KEY:METHOD=AES-128,URI=\"abematv-license://(.+)\",IV=(0x.+)$", item)
                        url = re.match(r"^/ts/(.+)/h264/\d+/(.+\.ts)$", item)
                        if key and self.key_raw != key[1]:
                            self.key_raw = key[1]
                            self.key = self._get_videokey_from_ticket(key[1])
                            self.iv = key[2]
                            logger.info("key: {}, iv: {}".format(self.key, self.iv))
                        elif url and not includes(self.segments, "url", item):
                            if self.slot != url[1]:
                                if self.slot is not None:
                                    convert = threading.Thread(target=self.convert,
                                                               kwargs={"slot": self.slot},
                                                               daemon=True)
                                    convert.start()
                                if self.target and self.target != url[1]:
                                    self.ignore = True
                                    logger.info("slot:{} : ignore".format(url[1]))
                                else:
                                    self.ignore = False
                                self.slot = url[1]
                            if self.ignore:
                                logger.debug("slot:{}, id:{} : skip".format(url[1], url[2]))
                            else:
                                self.segments.append(
                                    {"url": item, "downloaded": False, "slot": url[1], "filename": url[2],
                                     "key": self.key,
                                     "iv": self.iv, "extinf": lastline})
                                logger.info("slot:{}, id:{} : added".format(url[1], url[2]))
                        lastline = item
            except urllib.error as e:
                logger.debug(e)
            else:
                logger.debug("fetch: {} lines // {} segments".format(len(lines), len(self.segments)))
                time.sleep(1)

    def download(self):
        while True:
            self.downloading = True
            try:
                for index in range(len(self.segments)):
                    item = self.segments[index]
                    if not item["downloaded"]:
                        filename = re.match(r"/ts/.+/h264/\d+/(.+\.ts)", item["url"])[1]
                        if fetch("https://ds-linear-abematv.akamaized.net{}".format(item["url"]),
                                 os.path.join(self.tmpdir, "{}-{}".format(item["slot"], filename))):
                            self.segments[index]["filename"] = filename
                            self.segments[index]["downloaded"] = True
                            logger.info("slot:{}, id:{} : downloaded".format(item["slot"], filename))
                targets = []
                for item in self.segments:
                    if item["slot"] == self.downloaded_slot and self.slot != self.downloaded_slot:
                        targets.append(item)
                        self.segments.remove(item)
                if len(targets) > 0:
                    remove_var = threading.Thread(target=self.delete, kwargs={"targets": targets}, daemon=True)
                    remove_var.start()
            except urllib.error as e:
                logger.error(e)
            self.downloading = False
            time.sleep(1)

    def delete(self, targets):
        for item in targets:
            logger.info("slot:{}, id:{} : removed".format(item["slot"], item["filename"]))
            try:
                os.remove(os.path.join(self.tmpdir, "{}-{}".format(item["slot"], item["filename"])))
            except OSError as e:
                logger.error(e)

    def convert(self, slot):
        logger.info("slot:{} : convert start".format(slot))
        while downloading(self.segments, slot):
            time.sleep(1)
        segments = copy.copy(self.segments)
        files = [[]]
        last_pts = 0
        part_count = 0
        for item in segments:
            if item["slot"] == slot:
                with open(os.path.join(self.tmpdir, "{}-{}".format(item["slot"], item["filename"])), mode='rb') as f:
                    binary = f.read()
                decrypter = AES.new(item["key"], AES.MODE_CBC, bytes.fromhex(item["iv"].replace("0x", "")))
                binary_len = len(binary)
                if binary_len % 16 != 0:
                    binary = pad(binary, 16)
                binary = decrypter.decrypt(binary)
                with open(os.path.join(self.tmpdir, "{}-{}".format(item["slot"], item["filename"])), mode='wb') as f:
                    f.write(binary)
                meta = subprocess.run(["ffprobe", "-v", "quiet", "-print_format", "json", "-show_streams",
                                       os.path.join(self.tmpdir, "{}-{}".format(item["slot"], item["filename"]))],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
                logger.info("slot:{}, id:{} : decoded".format(item["slot"], item["filename"]))
                meta_data = json.loads(meta.stdout)
                if meta_data != {}:
                    if last_pts > meta_data["streams"][0]["start_pts"]:
                        part_count += 1
                        files.append([])
                    files[part_count].append("{}\n{}".format(
                        item["extinf"], os.path.join(self.tmpdir, "{}-{}".format(item["slot"], item["filename"]))))
                    last_pts = meta_data["streams"][0]["start_pts"]
        if len(files) > 1:
            parts = []
            for i in range(len(files)):
                with open(os.path.join(self.tmpdir, "{}-{}.m3u8".format(slot, i)), mode='w') as f:
                    f.write(
                        (
                            "#EXTM3U\n"
                            "#EXT-X-VERSION:3\n"
                            "#EXT-X-PLAYLIST-TYPE:VOD\n"
                            "#EXT-X-TARGETDURATION:13\n"
                            "#EXT-X-MEDIA-SEQUENCE:0\n"
                            "#EXT-X-DISCONTINUITY-SEQUENCE:0\n"
                            "{}\n"
                            "#EXT-X-ENDLIST"
                        ).format("\n".join(files[i])))
                code = subprocess.call(
                    ["ffmpeg", "-i", os.path.join(self.tmpdir, "{}-{}.m3u8".format(slot, i)), "-movflags", "faststart",
                     "-c", "copy", "-bsf:a", "aac_adtstoasc", os.path.join(self.tmpdir, "{}-{}.mp4".format(slot, i))])
                parts.append("file '{}'".format(os.path.join(self.tmpdir, "{}-{}.mp4".format(slot, i))))
                logger.debug("{}({}): convert finished with code {}".format(slot, i, code))
            with open(os.path.join(self.tmpdir, "{}.txt".format(slot)), mode='w') as f:
                f.write("\n".join(parts))
            code = subprocess.call(
                ["ffmpeg", "-f", "concat", "-safe", "0", "-i", os.path.join(self.tmpdir, "{}.txt".format(slot)),
                 "-movflags", "faststart", "-c", "copy", "-bsf:a", "aac_adtstoasc",
                 os.path.join(self.tmpdir, "{}.mp4".format(slot))])
        else:
            with open(os.path.join(self.tmpdir, "{}.m3u8".format(slot)), mode='w') as f:
                f.write(
                    (
                        "#EXTM3U\n"
                        "#EXT-X-VERSION:3\n"
                        "#EXT-X-PLAYLIST-TYPE:VOD\n"
                        "#EXT-X-TARGETDURATION:13\n"
                        "#EXT-X-MEDIA-SEQUENCE:0\n"
                        "#EXT-X-DISCONTINUITY-SEQUENCE:0\n"
                        "{}\n"
                        "#EXT-X-ENDLIST"
                    ).format("\n".join(files[0])))
            code = subprocess.call(
                ["ffmpeg", "-i", os.path.join(self.tmpdir, "{}.m3u8".format(slot)), "-movflags", "faststart", "-c",
                 "copy", "-bsf:a", "aac_adtstoasc", os.path.join(self.tmpdir, "{}.mp4".format(slot))])
        logger.debug("{}: convert finished with code {}".format(slot, code))
        verify = subprocess.run(["ffprobe", "-v", "quiet", "-print_format", "json", "-show_streams",
                                 os.path.join(self.tmpdir, "{}.mp4".format(slot))], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        verify_data = json.loads(verify.stdout)
        verify_video = False
        verify_audio = False
        try:
            for stream in verify_data["streams"]:
                if stream["codec_type"] == "video":
                    if stream["width"] is not None and stream["height"] is not None and stream[
                        "bit_rate"] is not None and \
                            stream["duration"] is not None:
                        verify_video = True
                elif stream["codec_type"] == "audio":
                    if stream["bit_rate"] is not None:
                        verify_audio = True
        except KeyError as e:
            logger.error(e)
        if verify_video and verify_audio:
            shutil.copy(os.path.join(self.tmpdir, "{}.mp4".format(slot)),
                        os.path.join(self.output_dir, "{}.mp4".format(slot)))
        if len(files) > 1:
            for i in range(len(files)):
                # shutil.copy(os.path.join(self.tmpdir, "{}-{}.mp4".format(slot, i)),os.path.join(self.output_dir, "{}-{}.mp4".format(slot, i)))
                os.remove(os.path.join(self.tmpdir, "{}-{}.mp4".format(slot, i)))
                os.remove(os.path.join(self.tmpdir, "{}-{}.m3u8".format(slot, i)))
        else:
            os.remove(os.path.join(self.tmpdir, "{}.m3u8".format(slot)))
        os.remove(os.path.join(self.tmpdir, "{}.mp4".format(slot)))
        self.downloaded_slot = slot


def includes(array, key, value):
    for item in array:
        if item[key] == value:
            return True
    return False


def downloading(array, value):
    for item in array:
        if item["slot"] == value and not item["downloaded"]:
            return True
    return False


def fetch(url, path, count=0):
    try:
        urllib.request.urlretrieve(url, path)
    except urllib.error as e:
        logger.error(e)
        try:
            os.remove(path)
        except OSError as e:
            logger.error(e)
        finally:
            if count > 10:
                return False
            count += 1
            fetch(url, path, count)
    else:
        return True
