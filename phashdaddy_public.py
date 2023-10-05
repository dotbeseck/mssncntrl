import itertools
import requests
import datetime
from bs4 import BeautifulSoup
from PIL import Image
import imagehash
import concurrent.futures
import sys
import os
import io
import dnstwist
import nltk

# from tqdm import tqdm
from tqdm.contrib.concurrent import thread_map

nltk.download("words")

from nltk.corpus import words

englishWords = words.words()

# Commonly Used Words in Phishing sites
word_list = [
    "localhost",
    "localhostsweepstakes",
    "localhostbank",
    "localhostspendingsweepz",
    "localhostwinner",
    "localhostandme",
    "localhostservice",
    "whyilocalhost",
    "memberslocalhosts",
    "localhostpridepaysweeps",
    "localhostbonus",
    "sweepstakes",
    "sweeptakes",
    "localhosttransactions",
    "localhost-member",
    "localhostsweepstake",
    "localhostsweeptakes",
    "winner",
    "whyllocalhost",
    "whylchlme",
    "winners",
    "winnersusd",
    "winnings",
    "www-localhost",
    "wwwlocalhostapp",
    "wwwchimapp",
    "sweepstakesbonus",
    "sweepstakeslocalhostin",
    "sweepstakeslocalhostagent",
    "sweepstakesearlypaid",
    "pridepaysweeps",
    "latinxheritagemonth",
    "financialservices",
    "congratulations",
    "communitylocalhost",
    "chlme",
    "clicktoactivate",
    "localhostsupport",
    "localhostpridepay",
    "localhostbancorp",
    "sweepstakes_online",
    "spotmemberco",
    "localhostboost",
]
# They just keep iterating with word + number so look at alot
number_list = list(range(1, 12000))
dns_number_list = list(range(1, 500))
# set domain to target
maindomain = "godaddysites.com"
# future plans
secondary_domain = "wixsite.com"

# list of images in the same directory as this script to use with phash...need more
known_images = [
    "localhostsign1.jpg",
    "randomlocalhost2.jpg",
    "sweeps1.jpg",
    "whyilocalhost2.jpg",
    "whyilocalhost5.jpg",
    "nerdwallet1.jpg",
    "randomlocalhost3.jpg",
    "whylocalhost6.jpg",
    "whyilocalhost3.jpg",
    "randomlocalhost1.jpg",
    "randomlocalhost4.jpg",
    "whyilocalhost.jpg",
    "whyilocalhost4.jpg",
    "10thbirthday.jpg",
]
# hash above images with phash for comparison
known_phashes = [imagehash.average_hash(Image.open(img)) for img in known_images]
# initiate dnstwist generated domains
lookalike_domains = []


# This whole class sole purpose is to not printthe list generated by dnstwist...
class Suppress_domain_list:
    def __enter__(self):
        self.original_stdout = sys.stdout
        sys.stdout = open(os.devnull, "w")

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout.close()
        sys.stdout = self.original_stdout


# Use dnstwist to get a good list of squatted domains using its fuzzers
domainList = ["localhost.com", "domain.com"]

for domain_name in domainList:
    with Suppress_domain_list():
        domain_variants = dnstwist.run(
            domain=domain_name,
            registered=False,
            format="list",
            dictionary="phishWords.dict",
        )

    # ignore these generated subdomains
    lookalike_domains = []
    for domain in domain_variants:
        if domain["domain"].startswith("xn--"):
            continue
        domain, _ = domain["domain"].split(".", 1)
        if domain.startswith("ch"):
            lookalike_domains.append(domain)

    print(
        f"For the domain {domain_name}, the lookalike domains are: {lookalike_domains}"
    )

# initialize a set of domains, used to make sure we only get unique domains
matched_domains = set()
file = f"gdphishing_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


# The working bit
def check_url(url):
    try:
        # get domain for the set above
        domain = url.split("/")[2]
        with requests.get(url, timeout=5) as response:
            # only care if domain is live
            if response.status_code == 200:
                # These variables get all the data for the images from the gd sites
                soup = BeautifulSoup(response.content, "html.parser")
                images = soup.find_all("meta", property="og:image")
                # iterate all found images
                for image in images:
                    img_url = image.get("content")
                    img_response = requests.get(img_url)
                    img = Image.open(io.BytesIO(img_response.content))
                    # compare the hashes
                    img_phash = imagehash.average_hash(img)
                    for known_phash in known_phashes:
                        # Seems to be the sweetspot so we dont trigger on other companies...like Dave.
                        if img_phash - known_phash < 10:
                            if domain not in matched_domains:
                                matched_domains.add(domain)
                                with open(file, "a") as f:
                                    f.write(url + "\n")
                            return
    # continue if we hit some exception
    except Exception as e:
        # pass
        print(f"Error on {url}: {e}")


urls1 = [
    f"http://{subdomain}{number}.{maindomain}"
    for subdomain in lookalike_domains
    for number in dns_number_list
]
urls2 = [
    f"http://{word}{number}.{maindomain}"
    for word in word_list
    for number in number_list
]

urls3 = [
    f"http://{word}{words}.{maindomain}" for word in word_list for words in englishWords
]

urls4 = [
    f"http://{words}{word}.{maindomain}" for word in word_list for words in englishWords
]

# concat the lists together (I will never forget how)
urls = urls1 + urls2 + urls3 + urls4

chunk_size = len(urls) // 4
for url_chunk in chunks(urls, chunk_size):
    thread_map(check_url, url_chunk, max_workers=30)

webhook_url = "https://SUBDOMAIN.tines.io/webhook//"

with open(file, "rb") as f:
    files = {"file": f}
    response = requests.post(webhook_url, files=files)
