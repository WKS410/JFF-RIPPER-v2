import argparse
import base64
import json
import os
import subprocess
from base64 import b64encode
from pathlib import Path
from typing import IO, Union
import pyfiglet
from rich import print
from typing import DefaultDict
import json
import random
import uuid
import token_jffplus
import httpx
from lxml import html
import os
import shutil
import json
import subprocess
import argparse
import sys
import pyfiglet
from rich import print
from typing import DefaultDict
from os import remove
import sys, math, uuid, base64, hashlib
import isodate, datetime, shutil, html
import requests, re, os, urllib, uuid
import subprocess, pycaption, argparse
import xmltodict, pathlib
import glob, ffmpy, time, json
import logging

from subprocess import Popen
from unidecode import unidecode
from os.path import isfile, join, basename

from titlecase import titlecase
from m3u8 import parse as m3u8parser
from helpers.logger import Logger
import requests
import xmltodict
from coloredlogs import ColoredFormatter, logging
from pathvalidate import sanitize_filename

from pywidevine.L3.cdm import deviceconfig
from pywidevine.L3.cdm.key import Key
from pywidevine.L3.decrypt.wvdecryptcustom import WvDecrypt

os.system('')
SERVICE = 'JFFP'
LOGLEVEL = logging.INFO
logger = Logger(SERVICE,LOGLEVEL).set_logger()

title = ('JFFP')
logger.info(f'{title}')

DOWNLOADS_PATH = Path(os.getcwd(), "downloads")
VAULT_FILE_PATH = Path(os.getcwd(), "jffplus.txt")

DEVICE = deviceconfig.device_android_generic

METADATA_URL = "https://watch.jff.jpf.go.jp/services/meta/v2/film/{id}/show_multiple"
PLAYBACK_URL = "https://watch.jff.jpf.go.jp/services/playback/streams/film/{id}"
LICENSE_URL = "https://watch.jff.jpf.go.jp/services/license/widevine/cenc?context={context}&d=v1bpqmdl.all"

tag_jffplus = "JFFP"
tag_user = "WKS"

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'x-auth-token': format(token_jffplus.token),
    'DNT': '1',
    'Connection': 'keep-alive',
    'Referer': 'https://watch.jff.jpf.go.jp/play/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'TE': 'trailers',
}

session = requests.Session()
session.headers.update(headers)


def read_pssh_from_bytes(bytes: bytes):
    pssh_offset = bytes.rfind(b'pssh')
    _start = pssh_offset - 4
    _end = pssh_offset - 4 + bytes[pssh_offset-1]
    pssh = bytes[_start:_end]
    return pssh


def log_subprocess_output(prefix: str, pipe: IO[bytes]):
    for line in iter(pipe.readline, b''):  # b'\n'-separated lines
        logger.debug('[%s]: %r', prefix, line.decode("utf8").strip())


def get_cert(license_url):
    res = session.post(
        license_url, data=base64.b64decode("CAQ="))
    if not res.ok:
        raise Exception("Could not get certificate: " + res.text)
    return base64.b64encode(res.content).decode()


def get_keys(pssh, license_url, cert_b64=None) -> tuple[bool, list[Key]]:
    wvdecrypt = WvDecrypt(init_data_b64=pssh, cert_data_b64=cert_b64,
                          device=DEVICE)

    challenge = wvdecrypt.get_challenge()

    widevine_license = session.post(
        url=license_url, data=challenge)
    license_b64 = b64encode(widevine_license.content)
    wvdecrypt.update_license(license_b64)
    Correct, keyswvdecrypt = wvdecrypt.start_process()
    if Correct:
        formatted_keys = []
        for key in keyswvdecrypt:
            kid, k = key.split(":")
            formatted_keys.append(Key(kid, "content", k))
        return Correct, formatted_keys


class Trailer:
    def __init__(self) -> None:
        pass


class Bonus:
    def __init__(self) -> None:
        pass


class CastMember:
    def __init__(self) -> None:
        pass


class CrewMember:
    def __init__(self, data) -> None:
        self.name: str = data["name"]
        self.job: str = data["job"]


class Studio:
    def __init__(self) -> None:
        pass


class SubtitleTrack:
    def __init__(self, data: dict) -> None:
        self.language: str = data["language"]
        self.language_name: str = data["language_name"]
        self.type: str = data["type"]
        self.path: str = data["path"]


class Film:
    def __init__(self, data: dict) -> None:
        image_urls = data["image_urls"]

        self.trailers: list[Trailer] = []
        self.bonuses: list[Bonus] = []
        self.cast: list[CastMember] = []
        self.crew: list[CrewMember] = []
        self.studio: list[Studio] = []
        self.release_date: str = data["release_date"]
        self.runtime: int = data["runtime"]
        self.tagline: str = data["tagline"]
        self.overview: str = data["overview"]
        self.genres: list[str] = data["genres"]
        self.title: str = data["title"]
        self.title_safe: str = (sanitize_filename(self.title)).replace('\'','')
        self.slug: str = data["slug"]
        self.film_id: int = data["film_id"]
        self.id: int = data["id"]
        self.subtitle_tracks: list[SubtitleTrack] = []
        self.seo_title: str = data["seo_title"]
        self.seo_keywords: str = data["seo_keywords"]
        self.seo_description: str = data["seo_description"]
        self.image_urls: dict[str, str] = {
            "portrait": image_urls["portrait"],
            "landscape": image_urls["landscape"],
            "header": image_urls["header"],
            "carousel": image_urls["carousel"],
            "bg": image_urls["bg"],
            "classification": image_urls["classification"],
            "seo": image_urls["seo"],
        }
        self.classifications: dict[str,
                                   dict[str, str]] = data["classifications"]
        self.subtitles: list[str] = data["subtitles"]

        for trailer in data["trailers"]:
            self.trailers.append(Trailer(trailer))

        for bonus in data["bonuses"]:
            self.bonuses.append(Bonus(bonus))

        for member in data["cast"]:
            self.cast.append(CastMember(member))

        for member in data["crew"]:
            self.crew.append(CrewMember(member))

        for studio in data["studio"]:
            self.studio.append(Studio(studio))

        for subtitle in data["subtitle_tracks"]:
            self.subtitle_tracks.append(SubtitleTrack(subtitle))


class PlaybackStream:
    def __init__(self, data) -> None:
        self.url: str = data["url"]
        self.width: int = data["width"]
        self.height: int = data["height"]
        self.bitrate: int = data["bitrate"]
        self.encoding_type: str = data["encoding_type"]
        self.drm_key_encoded: str = data["drm_key_encoded"]
        self.drm_type: list[str] = data["drm_type"]
        self.watermark: str = data["watermark"]


class PlaybackInfo:
    def __init__(self, data: dict) -> None:
        self.play_token = data["play_token"]
        self.playback_progress = data["playback_progress"]
        self.streams: list[PlaybackStream] = []
        self.ad_tag = data["ad_tag"]
        self.config = data["config"]

        for stream in data["streams"]:
            self.streams.append(PlaybackStream(stream))

def get_film_metadata(film_id: int) -> Film:
    """
    Gets the metadata for a film.
    returns an array of dicts
    """
    res = session.get(METADATA_URL.format(id=film_id))
    if not res.ok:
        raise Exception(f"Failed to get film information: {res.text}")

    return Film(res.json()[0])


def get_film_streams(film: Film) -> PlaybackInfo:
    res = session.get(PLAYBACK_URL.format(id=film.film_id))
    if not res.ok:
        raise Exception(
            f"Failed to get streams for film {film.title}: {res.text}")

    return PlaybackInfo(res.json())

# try:
#     correct, keys = WV_Function(pssh, license_url)

#     if correct:
#         print()
#         for key in keys:
#             print('--key ' + key)
# except Exception as e:
#     print(e)


def download_subtitle(film: Film, subtitles_path: Path, subtitle: SubtitleTrack):
    ext = subtitle.path.split(".")[-1]
    subtitle_filename = f"{film.title_safe}_{subtitle.language}.{ext}"
    subtitle_path = Path(subtitles_path, subtitle_filename)
    if subtitle_path.exists():
        logger.warning(
            f"[+] Subtitle already downloaded {subtitle_filename}, skipping")
        return

    res = session.get(subtitle.path)
    if not res.ok:
        raise Exception(
            f"Failed to download subtitle {subtitle_filename}: {res.text}")

    subtitle_path.write_bytes(res.content)
    logger.info(f"Downloaded subtitle {subtitle_filename}")


def get_pssh(url: str, range: str) -> bytes:
    res = session.get(url, headers={"range": f"bytes={range}"}, stream=True)
    if not res.ok:
        raise Exception(f"Failed to get track url {url}: {res.text}")

    return read_pssh_from_bytes(res.content)
    



def get_vault() -> list[dict[str, str]]:
    if VAULT_FILE_PATH.exists():
        with VAULT_FILE_PATH.open() as vault_file:
            return json.load(vault_file)
    else:
        # create vault file with empty array
        with VAULT_FILE_PATH.open("w") as vault_file:
            json.dump([], vault_file)
        return []


def save_vault(vault: list[str]):
    with VAULT_FILE_PATH.open("w") as vault_file:
        json.dump(vault, vault_file)

def get_key_from_vault(kid: str) -> list[Key]:
    VAULT = get_vault()
    result = next((x for x in VAULT if x["kid"] == kid), None)
    if result:
        return [Key(result["kid"], "content", result["key"])]
    else:
        return None

def convert_size(size_bytes):
    if size_bytes == 0:
        return '0bps'
    else:
        s = round(size_bytes / 1000, 0)
        return '%ikb/s' % s


def main():
    parser = argparse.ArgumentParser(
        description='JFF Ripper')
    parser.add_argument('film_id', type=str, help="Film ID", metavar="film_id")
    parser.add_argument("-d", "--debug", dest="debug",
                        action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    
    currentFile = __file__
    realPath = os.path.realpath(currentFile)
    dirPath = os.path.dirname(realPath)
    dirName = os.path.basename(dirPath)
    dir = dirPath
    
    reexe = dirPath + '/RE.exe'
    shakaexe = dirPath + '/shaka.exe'
    ffmpegexe = dirPath + '/ffmpeg.exe'
    mkvmergeexe = dirPath + '/mkvmerge.exe'

    film_id = args.film_id
    if args.debug:
        logging.root.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        stream.setLevel(logging.DEBUG)

    DOWNLOADS_PATH.mkdir(exist_ok=True)

    logger.info("[+] Getting film information...")
    film = get_film_metadata(film_id)
    film_path = Path(DOWNLOADS_PATH, film.title_safe)
    subtitles_path = Path(film_path, "subtitles")

    video_enc_filename = f"{film.title_safe}.enc-video.mp4"
    audio_dec_filename = f"{film.title_safe}.audio.mp4"
    video_dec_filename = f"{film.title_safe}.video.mp4"
    final_filename = f"{film.title_safe}.mp4"

    video_enc_file = Path(film_path, video_enc_filename)
    audio_dec_file = Path(film_path, audio_dec_filename)
    video_dec_file = Path(film_path, video_dec_filename)
    final_file = Path(film_path, final_filename)

    if final_file.exists():
        logger.warning(
            f"[+] File already downloaded {final_filename}, skipping")
        return

    film_path.mkdir(exist_ok=True)
    subtitles_path.mkdir(exist_ok=True)

    # # download subtitles
    logger.info(f"[+] Downloading {len(film.subtitle_tracks)} subtitles...")
    for subtitle in film.subtitle_tracks:
        try:
            download_subtitle(film, subtitles_path, subtitle)
        except Exception as e:
            logger.exception(e)

    # get the film playback information
    logger.info("[+] Getting film streams...")
    playback_data = get_film_streams(film)
    dash_stream = next(
        (x for x in playback_data.streams if x.encoding_type == "hd_dash"), None)
    if not dash_stream:
        raise Exception("No dash stream found")

    # get the dash manifest
    logger.info("[+] Getting dash manifest...")
    dash_res = session.get(dash_stream.url)
    dash_url2 = ([f"{dash_stream.url}"])
    logger.info(dash_url2)
    if not dash_res.ok:
        raise Exception(
            f"Failed to get dash manifest: {dash_res.text}")
    manifest = xmltodict.parse(dash_res.text)
    sets = manifest["MPD"]["Period"]["AdaptationSet"]
    for x in sets:
        if x['@contentType'] == 'video':
            video_set = x
        if x['@contentType'] == 'audio':
            audio_set = x
    video_rep = video_set["Representation"]
    audio_rep = audio_set["Representation"][-1] if isinstance(
        audio_set["Representation"], list) else audio_set["Representation"]

    video_url = video_rep["BaseURL"]
    audio_url = audio_rep["BaseURL"]

    video_height = video_set['@height']
    video_width = video_set['@width']

    if 'mp4' in audio_rep["@codecs"]:
        ac = 'aac'
    elif 'ec-3' in audio_rep["@codecs"]:
        ac = 'eac3'
    elif 'ac-3' in audio_rep["@codecs"]:
        ac = 'ac3'


    logger.info('[+] VIDEO - resolution: ' + video_width + 'x' + video_height + ' - ' + convert_size(int(video_rep['@bandwidth']) * 0.853) + ' - fps: ' + video_set['@frameRate'])
    logger.info('[+] AUDIO - audio-codec: ' + ac + ' - ' + convert_size(int(audio_rep['@bandwidth']) * 0.853))
    audio_aac = "AAC"
    audio_eac3 = "DDP"
    audio_ac3 = "DD"
    audio_dts = "DTS"
    audio_2_ch = "2.0"
    audio_6_ch = "5.1"
    audio_8_ch = "7.1"

    # get video kid
    logger.info("[+] Getting video kid...")
    video_kid: str = video_set["ContentProtection"][0]["@cenc:default_KID"]
    video_kid = video_kid.lower().replace("-", "")
    video_kid2 = ([f"{video_kid}"])
    logger.info(f"[+] {video_kid2}")

    # get video pssh
    logger.info("[+] Getting video pssh...")
    video_pssh = get_pssh(
        video_url, video_rep["SegmentBase"]["Initialization"]["@range"])
    video_pssh_b64 = base64.b64encode(video_pssh).decode("utf-8")
    video_pssh_b642 = ([f"{video_pssh_b64}"])
    logger.info(f"[+] {video_pssh_b642}")

    # get audio kid
    logger.info("[+] Getting audio kid...")
    audio_kid: str = audio_set["ContentProtection"][0]["@cenc:default_KID"]
    audio_kid = audio_kid.lower().replace("-", "")
    audio_kid2 = ([f"{audio_kid}"])
    logger.info(f"[+] {audio_kid2}")

    # get audio pssh
    logger.info("[+] Getting audio pssh...")
    audio_pssh = get_pssh(
        audio_url, audio_rep["SegmentBase"]["Initialization"]["@range"])
    audio_pssh_b64 = base64.b64encode(audio_pssh).decode("utf-8")
    audio_pssh_b642 = ([f"{audio_pssh_b64}"])
    logger.info(f"[+] {audio_pssh_b642}")

    # get key video
    keys = get_key_from_vault(video_kid)
    if not keys:
        license_url = LICENSE_URL.format(context=dash_stream.drm_key_encoded)
        cert_b64 = get_cert(license_url)
        correct, keys = get_keys(video_pssh_b64, license_url, cert_b64)
        if not correct:
            raise Exception("Failed to get keys")

    # find matching key
    logger.info("[+] VIDEO KEY:...")
    key = next(
        (x for x in keys if x.kid == video_kid), None)
    if not key:
        raise Exception("No matching key")

    keyvideo = " ".join([f"{key.kid}:{key.key}"])
    key_video2 = ([f"{keyvideo}"])
    logger.info(key_video2)

    # get key audio
    keys = get_key_from_vault(audio_kid)
    if not keys:
        license_url = LICENSE_URL.format(context=dash_stream.drm_key_encoded)
        cert_b64 = get_cert(license_url)
        correct, keys = get_keys(audio_pssh_b64, license_url, cert_b64)
        if not correct:
            raise Exception("Failed to get keys")

    # find matching key
    logger.info("[+] AUDIO KEY:")
    key = next(
        (x for x in keys if x.kid == audio_kid), None)
    if not key:
        raise Exception("No matching key")

    keyaudio = " ".join([f"{key.kid}:{key.key}"])
    key_audio2 = ([f"{keyaudio}"])
    logger.info(key_audio2)
    
    logger.info(f"[+] Downloading and muxing...")
    film_title_safe2 = ([f"{film.title_safe}.{video_height}p.{tag_jffplus}.WEB-DL.{audio_aac}{audio_2_ch}.x264-{tag_user}.mkv"])
    logger.info(film_title_safe2)
    subprocess.run([reexe, f"{dash_stream.url}" , "--mp4-real-time-decryption", f"--tmp-dir={film_path}", f"--save-dir={film_path}", "--download-retry-count=5", "--check-segments-count=false", "--no-date-info", "--log-level=OFF", "--use-shaka-packager", "--auto-select", "--concurrent-download", "--key", f"{keyvideo}" , "--key", f"{keyaudio}" , '--save-name', f'{film.title_safe}.{video_height}p.{tag_jffplus}.WEB-DL.{audio_aac}{audio_2_ch}.x264-{tag_user}', f"--mux-after-done", f"format=mkv:muxer=mkvmerge:bin_path=mkvmerge.exe"])
    logger.info(f"[+] Done...")
    



if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)