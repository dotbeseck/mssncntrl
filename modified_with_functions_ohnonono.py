import certstream
import csv
import requests
import dnstwist
import nltk
import re
from bs4 import BeautifulSoup
from PIL import Image
import imagehash
import time
import tempfile
# Other necessary imports

def get_image_urls_from_website(url):
    """Fetches all image URLs from a given website."""
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    imgs = soup.find_all("img")
    img_urls = [img['src'] for img in imgs if 'src' in img.attrs]
    
    # Convert relative URLs to absolute URLs if necessary
    img_urls = [requests.compat.urljoin(url, img_url) for img_url in img_urls]
    
    return img_urls

def get_perceptual_hash(img_url):
    """Fetches an image from a given URL and computes its perceptual hash."""
    try:
        response = requests.get(img_url)
        img = Image.open(BytesIO(response.content))
        p_hash = imagehash.phash(img)
        return p_hash
    except UnidentifiedImageError:
        # Ignoring the "cannot identify image file" error and returning None
        return None

nltk.download("words")

from nltk.corpus import words

english_words = set(words.words())

keywords = [
    "chime",
    "chimesweepstakes",
    "chimebank",
    "chimespendingsweepz",
    "chimewinner",
    "chimeandme",
    "chimeservice",
    "whyichime",
    "memberschimes",
    "chimepridepaysweeps",
    "chimebonus",
    "sweepstakes",
    "sweeptakes",
    "chimetransactions",
    "chime-member",
    "chimesweepstake",
    "chimesweeptakes",
    "winner",
    "whylchime",
    "whylchlme",
    "winners",
    "winnersusd",
    "winnings",
    "www-chime",
    "wwwchimeapp",
    "wwwchimapp",
    "sweepstakesbonus",
    "sweepstakeschimein",
    "sweepstakeschimeagent",
    "sweepstakesearlypaid",
    "pridepaysweeps",
    "latinxheritagemonth",
    "financialservices",
    "congratulations",
    "communitychime",
    "chlme",
    "clicktoactivate",
    "chimesupport",
    "chimepridepay",
    "chimebancorp",
    "sweepstakes_online",
    "spotmemberco",
    "chimeboost",
    "google"
]
target_domain = "chime.com"
known_images = [
    "chimesign1.jpg",
    "randomchime2.jpg",
    "sweeps1.jpg",
    "whyichime2.jpg",
    "whyichime5.jpg",
    "nerdwallet1.jpg",
    "randomchime3.jpg",
    "whychime6.jpg",
    "whyichime3.jpg",
    "randomchime1.jpg",
    "randomchime4.jpg",
    "whyichime.jpg",
    "whyichime4.jpg",
    "10thbirthday.jpg",
    "google.png",
    "nextcloud.png"
]  

known_phashes = [imagehash.average_hash(Image.open(img)) for img in known_images]

def generate_typosquatted_domains(domain):
    lookalike_domains = []
    
    domain_variants = dnstwist.run(
        domain=target_domain,
        registered=False,
        format="list",
        fuzzers="addition,bitsquatting,dictionary,homoglyph,insertion,repetition,transposition",
        #dictionary="phishWords.dict",
    )
    
    for domain_variant in domain_variants:
        if domain_variant["domain"].startswith("xn--"):
            continue
        domain_name, _ = domain_variant["domain"].split(".", 1)
        if domain_name.startswith("ch") and domain_name not in english_words:
            lookalike_domains.append(domain_name)
    
    special_pattern_lookalike_domains = r"\b(?:{})\b".format(
        "|".join(re.escape(lookalike_domain) for lookalike_domain in lookalike_domains)
    )
    return special_pattern_lookalike_domains

special_pattern_lookalike_domains = generate_typosquatted_domains(target_domain)
print (special_pattern_lookalike_domains)
def check_image_hash(domain):
    for protocol in ["https://", "http://"]:
        url = protocol + domain
        try:
            # Fetch the images from the URL using requests or another method
            response = requests.get(url, timeout=10)  # Set a reasonable timeout
            if response.status_code == 200:
                # These variables get all the data for the images from the gd sites
                soup = BeautifulSoup(response.content, "html.parser")
                images = soup.find_all('img')
                if not images:
                    print(f"No Images found on: {domain}")
                    continue
                # iterate all found images
                for image in images:
                    img_url = image.get("content")
                    img_response = requests.get(img_url)
                    img = Image.open(io.BytesIO(img_response.content))
                    # compare the hashes
                    img_phash = imagehash.average_hash(img)
                    for known_phash in known_phashes:
                        distance = img_phash - compute_phash(known_phash)  # Compute hamming distance
                        print(f"Phash score for domain {domain}: {distance}")  # Print the score
                        # Seems to be the sweetspot so we dont trigger on other companies...like Dave.
                        if img_phash - known_phash < 100:
                            if domain not in matched_domains:
                                matched_domains.add(domain)
                                with open(file, "a") as f:
                                    f.write(url + "\n")
                            return
                if "malicious_content" in response.text:  
                    return True
            else:
                continue
        except requests.RequestException:
            continue  # If one protocol fails, it will try the next one
    return False

def callback(message, context):
    if message['message_type'] == "certificate_update":
        domains = message['data']['leaf_cert']['all_domains']
        with tempfile.NamedTemporaryFile(delete=False, mode="a") as temp_file:  # Open a temporary file in append mode
            for domain in domains:
                if any(keyword in domain for keyword in keywords) or re.search(special_pattern_lookalike_domains, domain):
                    temp_file.write(domain + '\n')
                    temp_file.flush()  # Ensure the data is written to disk
                    delay_seconds = 60  # For example, a 5 second delay
                    time.sleep(delay_seconds)  # Introduce a delay
                    print (domain)
                    if check_image_hash(domain):
                        print(f"Potential malicious domain found: {domain}")
                        with open("output.csv", "a") as f:
                            writer = csv.writer(f)
                            writer.writerow([domain])

certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
