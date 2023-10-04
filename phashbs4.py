import requests
from bs4 import BeautifulSoup
from PIL import Image, UnidentifiedImageError
import imagehash
from io import BytesIO

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

def main():
    url = input("Enter the website URL (e.g., google.com, cnn.com): ")
    
    # Prepend https:// if it doesn't exist
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        image_urls = get_image_urls_from_website(url)
        
        for img_url in image_urls:
            try:
                p_hash = get_perceptual_hash(img_url)
                if p_hash:
                    print(f"URL: {img_url}, Perceptual Hash: {p_hash}")
            except requests.RequestException:
                # Suppressing the "No connection adapters were found for" error
                pass
            except Exception as e:
                print(f"Failed to process {img_url}. Reason: {e}")
    except requests.RequestException:
        print(f"Failed to fetch content from {url}.")
    except Exception as e:
        print(f"An error occurred. Reason: {e}")

if __name__ == "__main__":
    main()
