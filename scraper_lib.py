import re
import random
import asyncio
import time
import cloudscraper
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.78 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
]

CC_PATTERN = re.compile(
    r'(?P<cc>\b\d{13,19}\b)'
    r'.*?'
    r'(?P<month>\b\d{1,2}\b).*?'
    r'(?P<year>\b\d{2,4}\b).*?'
    r'(?P<cvv>\b\d{3,4}\b)',
    re.DOTALL | re.IGNORECASE
)

# Pre-compiled for speed
SIMPLE_CC_RE = re.compile(r'\b\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}\b')


def extract_cc(text):
    """Extract credit card patterns from text. Optimised with pre-compiled regex."""
    found = set()
    found.update(SIMPLE_CC_RE.findall(text))

    for match in CC_PATTERN.finditer(text):
        cc = match.group('cc')
        if not (13 <= len(cc) <= 19):
            continue
        month = match.group('month').zfill(2)
        year = match.group('year')
        if len(year) == 2:
            year = "20" + year if int(year) <= 50 else "19" + year
        year = year[-2:]
        cvv = match.group('cvv')
        found.add(f"{cc}|{month}|{year}|{cvv}")
    return found


def _build_session():
    """Build a cloudscraper session that bypasses Cloudflare protection."""
    s = cloudscraper.create_scraper(
        browser={
            'browser': 'chrome',
            'platform': 'windows',
            'desktop': True,
        }
    )
    s.headers.update({
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    })
    return s


class ForumScraper:
    def __init__(self, username, password, domain, login_url, login_page,
                 start_url, status_callback=None, max_workers=15):
        self.username = username
        self.password = password
        self.domain = domain
        self.base_url = f"https://{domain}"
        self.login_url = login_url
        self.login_page = login_page
        self.start_url = start_url
        self.status_callback = status_callback
        self.max_workers = max_workers
        self.session = _build_session()
        self.running = False
        self._seen_threads = set()  # dedup across pages

    async def _log(self, msg):
        if self.status_callback:
            try:
                await self.status_callback(msg)
            except Exception:
                pass

    def login(self):
        """Login to the forum using requests."""
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        try:
            r = self.session.get(self.login_page, timeout=12)
            soup = BeautifulSoup(r.text, 'html.parser')

            try:
                token = soup.find("input", {"name": "_xfToken"})["value"]
            except TypeError:
                return False, "Could not find _xfToken. Cloudflare or IP ban?"

            data = {
                "login": self.username,
                "password": self.password,
                "_xfToken": token,
                "remember": "1"
            }

            self.session.post(self.login_url, data=data, timeout=12)

            # Verify login
            test = self.session.get(self.base_url + "/", timeout=12)
            text_lower = test.text.lower()
            if self.username.lower() in text_lower or "log out" in text_lower or "deconnexion" in text_lower:
                return True, "Login successful!"
            else:
                return False, "Login failed (session check failed)."

        except Exception as e:
            return False, f"Login exception: {str(e)}"

    def scrape_thread(self, url):
        """Scrape a single thread for CC data."""
        try:
            r = self.session.get(url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            parts = [w.get_text(separator="\n") for w in soup.select('div.bbWrapper')]
            content = "\n".join(parts)
            cards = extract_cc(content)
            if cards:
                title = soup.title.string if soup.title else "Unknown Thread"
                return (title, cards)
        except Exception:
            pass
        return None

    def _scrape_threads_batch(self, thread_urls):
        """Scrape a batch of threads in parallel using ThreadPoolExecutor."""
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.scrape_thread, url): url for url in thread_urls}
            for future in futures:
                try:
                    r = future.result(timeout=20)
                    if r:
                        results.append(r)
                except Exception:
                    pass
        return results

    async def start(self):
        """Main async loop for scraping — fast & unlimited."""
        self.running = True
        await self._log("🔑 Verifying credentials...")

        # Run login in thread to avoid blocking async loop
        success, msg = await asyncio.to_thread(self.login)
        if not success:
            await self._log(f"❌ {msg}")
            self.running = False
            return

        await self._log("✅ Login Verified. Starting scraper...")

        page = 1
        total_found = 0
        start_time = time.time()

        try:
            while self.running:
                url = self.start_url if page == 1 else f"{self.start_url}page-{page}"

                # Fetch page
                try:
                    r = await asyncio.to_thread(self.session.get, url, timeout=12)
                    soup = BeautifulSoup(r.text, 'html.parser')
                except Exception as e:
                    await self._log(f"⚠️ Error fetching page {page}: {e}")
                    break

                # Collect thread URLs (dedup)
                thread_urls = []
                for a in soup.select('div.structItem-title a[href*="/threads/"]'):
                    href = a['href'].split('?')[0]
                    if not href.startswith('http'):
                        full_url = self.base_url + href
                    else:
                        full_url = href

                    if full_url in self._seen_threads:
                        continue
                    self._seen_threads.add(full_url)

                    title = a.get_text(strip=True)
                    if any(kw in title.lower() for kw in ["giveaway", "contest", "staff", "banned"]):
                        continue
                    thread_urls.append(full_url)

                if not thread_urls:
                    await self._log("🛑 No more threads found. Stopping.")
                    break

                # Scrape all threads in parallel
                results = await asyncio.to_thread(self._scrape_threads_batch, thread_urls)

                # Batch report
                page_cards = 0
                for title, cards in results:
                    msg = f"💳 Found {len(cards)} cards in: {title}\n" + "\n".join(cards)
                    await self._log(msg)
                    page_cards += len(cards)

                total_found += page_cards
                elapsed = time.time() - start_time
                speed = total_found / elapsed if elapsed > 0 else 0

                await self._log(
                    f"📊 Page {page}: {page_cards} cards | "
                    f"Total: {total_found} | "
                    f"Threads: {len(self._seen_threads)} | "
                    f"Speed: {speed:.1f} cards/sec"
                )

                page += 1
                # Short delay to avoid rate limiting
                await asyncio.sleep(0.5)

        except Exception as e:
            await self._log(f"❌ Scraper crashed: {e}")
        finally:
            self.running = False
            elapsed = time.time() - start_time
            await self._log(
                f"🏁 Scraping finished. "
                f"Total: {total_found} cards | "
                f"Pages: {page - 1} | "
                f"Threads: {len(self._seen_threads)} | "
                f"Time: {elapsed:.1f}s"
            )

    def stop(self):
        self.running = False
