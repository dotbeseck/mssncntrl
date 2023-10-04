import certstream
import csv
import requests
import dnstwist
import nltk
import re
from bs4 import BeautifulSoup
from PIL import Image, UnidentifiedImageError
import imagehash
import time
import tempfile
from io import BytesIO
# Other necessary imports

def get_image_urls_from_website(url):
    """Fetches all image URLs from a given website."""
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    
    # Find all image tags
    imgs = soup.find_all("img")
    
    # Extract 'src', 'data-src', 'srcset', 'data-srcset', 'data-original', and 'data-lazy-src' attributes
    img_urls = [img['src'] for img in imgs if 'src' in img.attrs]
    img_urls += [img['data-src'] for img in imgs if 'data-src' in img.attrs]
    img_urls += [url.split(" ")[0] for img in imgs for url in img.get('srcset', '').split(",")]
    img_urls += [url.split(" ")[0] for img in imgs for url in img.get('data-srcset', '').split(",")]
    img_urls += [img['data-original'] for img in imgs if 'data-original' in img.attrs]
    img_urls += [img['data-lazy-src'] for img in imgs if 'data-lazy-src' in img.attrs]
    
    # Extract URLs from inline CSS background images
    elements_with_backgrounds = soup.select('[style*="background-image: url("]')
    for elem in elements_with_backgrounds:
        style_content = elem['style']
        bg_url_start = style_content.find('background-image: url(') + len('background-image: url(')
        bg_url_end = style_content.find(')', bg_url_start)
        if bg_url_start != -1 and bg_url_end != -1:
            bg_url = style_content[bg_url_start:bg_url_end].strip('"').strip("'")
            img_urls.append(bg_url)
    
    # Convert relative URLs to absolute URLs if necessary
    img_urls = [requests.compat.urljoin(url, img_url) for img_url in img_urls]
    
    # Deduplicate the list
    img_urls = list(set(img_urls))
    
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
    "google",
    "okta"
]
target_domain = "localhost.com"
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
    "google.png",
    "nextcloud.png",
    "ok5ta.png"
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
    # Prepend https:// if it doesn't exist
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain

    matched_domains = set()
    image_hashes = []  # List to store the computed perceptual hashes

    try:
        image_urls = get_image_urls_from_website(domain)
        
        for img_url in image_urls:
            try:
                img_phash = get_perceptual_hash(img_url)
                if img_phash:
                    image_hashes.append(img_phash)  # Append the hash to the list
                    for known_phash in known_phashes:
                        distance = img_phash - known_phash  # Compute hamming distance
                        # Seems to be the sweetspot so we don't trigger on other companies...like Dave.
                        if img_phash - known_phash < 100:
                            if domain not in matched_domains:
                                matched_domains.add(domain)
                                return True
            except requests.RequestException:
                pass
            except Exception as e:
                print(f"Failed to process {img_url}. Reason: {e}")
        
        # Print the computed image hashes or a message if no hashes were found
        if not image_hashes:
            print("No image hashes were found for the domain:", domain)
        else:
            print("Image hashes for the domain", domain, "are:")
            for hash_val in image_hashes:
                print(hash_val)

    except requests.RequestException:
        pass
    except Exception as e:
        print(f"An error occurred. Reason: {e}")
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
                        with open("output1.csv", "a") as f:
                            writer = csv.writer(f)
                            writer.writerow([domain])

certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
