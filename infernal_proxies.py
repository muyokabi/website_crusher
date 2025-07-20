#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡
⚡                                               ⚡
⚡  INFERNAL PROXY MAELSTROM                     ⚡
⚡  A MODULE SO DARK IT MAKES TOR ITS SLAVE      ⚡
⚡                                               ⚡
⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡
"""

import random
import time
import os
import socket
import ssl
import requests
import base64
from stem import Signal
from stem.control import Controller
from stem.util.log import get_logger
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from concurrent.futures import ThreadPoolExecutor

# ====== ABYSSAL CONFIGURATION ====== #
TOR_PORTS = [9050, 9150, 9060]  # Added chaos port
PROXY_DEATH_TIMEOUT = 6.66  # Seconds before declaring proxy dead
MAX_PROXY_AGE = 13 * 60  # 13 minutes in seconds
DEMONIC_PROXY_API = "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc"

# ====== VOID-TOUCHED LOGGER ====== #
log = get_logger()
log.propagate = False

# ====== QUANTUM PROXY VALIDATION ====== #
class QuantumValidator:
    def __init__(self):
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=b"abyssal_salt",
            iterations=666666
        )

    def _quantum_fingerprint(self, proxy):
        """Create unbreakable proxy signature"""
        return self.kdf.derive(proxy.encode())

# ====== NINTH CIRCLE PROXY HANDLER ====== #
class InfernalProxies(QuantumValidator):
    def __init__(self):
        super().__init__()
        self.proxy_graveyard = set()
        self.proxy_rebirth_queue = []
        self.last_harvest = 0
        self._load_abyssal_proxies()
        self.executor = ThreadPoolExecutor(max_workers=13)

    def _blood_encrypted_read(self, filename):
        """Read files with abyssal encryption"""
        with open(filename, 'rb') as f:
            data = f.read()
        return data.splitlines()

    def _load_abyssal_proxies(self):
        """Load proxies whether they come as full URLs or raw IP:port"""
        self.proxy_list = []
        
        try:
            with open("3k_proxies.txt", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Handle both formats:
                    # "http://203.243.63.16:80" AND "203.243.63.16:80"
                    if "://" in line:  # Full URL format
                        self.proxy_list.append(line)
                    else:  # Raw IP:port format
                        if ":" in line and len(line.split(":")) == 2:
                            self.proxy_list.append(f"http://{line}")
        
            log.warning(f"⚡ PROCESSED {len(self.proxy_list)} PROXIES (ALL FORMATS ACCEPTED) ⚡")
        
        except Exception as e:
            log.error(f"🔥 ABYSSAL LOAD FAILURE: {str(e)}")
            # Fallback to emergency raw IP:port proxies
            self.proxy_list = [
                "http://203.243.63.16:80",
                "http://3.24.58.156:3128",
                "http://95.217.104.21:24815"
            ]
        
        # 2. Harvest fresh proxies if file is stale
        if time.time() - self.last_harvest > 666:  # Every 11 minutes
            self._harvest_demonic_proxies()

    def _harvest_demonic_proxies(self):
        try:
            response = requests.get(
                DEMONIC_PROXY_API,
                headers={"X-Infernal-Sigil": base64.b64encode(os.urandom(32))},
                timeout=13
            )
            new_proxies = [f"http://{p['ip']}:{p['port']}" for p in response.json()['data']]
            self.proxy_list.extend(new_proxies)
        except Exception as e:
            log.error(f"🔥 API HARVEST FAILED: {e}")

    def _classify_proxy(self, speed):
        if speed < 1.3: return "ARCHDEMON"
        elif speed < 3.3: return "LESSER_DEMON"
        else: return "TORMENTED_SOUL"

    def _test_proxy_virility(self, proxy):
        """Test proxy while injecting chaos into the mortal realm"""
        test_urls = [
            ("http://checkip.amazonaws.com", "http"),
            ("https://api.ipify.org", "https"),
            ("http://icanhazip.com", "http")
        ]
        
        for url, protocol in test_urls:
            try:
                proxy_url = self._normalize_proxy(proxy)
                start = time.time()
                r = requests.get(
                    url,
                    proxies={protocol: proxy_url},
                    timeout=6.66,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                )
                if r.status_code == 200:
                    speed = time.time() - start
                    if speed < 3.33:  # Speed threshold
                        return True
                    else:
                        log.warning(f"🔥 TOO SLOW: {proxy_url} ({speed:.2f}s)")
                else:
                    log.warning(f"🔥 REJECTED: {proxy_url} (HTTP {r.status_code})")
            except Exception as e:
                log.warning(f"🔥 TEST FAILED: {proxy_url} ({str(e)})")
                continue
        
        return False

    def rotate_tor(self, violent=False):
        """Command TOR to assume new identities with optional violence"""
        try:
            with Controller.from_port(port=random.choice(TOR_PORTS)) as ctrl:
                ctrl.authenticate()
                if violent:
                    ctrl.signal(Signal.HALT)  # Brutal restart
                    time.sleep(1.3)
                    ctrl.signal(Signal.START)
                else:
                    ctrl.signal(Signal.NEWNYM)
                # Add entropy to the void
                os.urandom(666)
        except Exception as e:
            log.error(f"🔥 TOR ROTATION FAILED: {str(e)}")
            if "Socket" in str(e):
                self._resurrect_tor()

    def _resurrect_tor(self):
        """Bring TOR back from the dead with dark rituals"""
        log.error("🔥 TOR HAS FALLEN! PERFORMING RESURRECTION...")
        
        # 1. Kill all tor processes violently
        os.system("pkill -9 tor")
        time.sleep(1.3)
        
        # 2. Restart with infernal config
        os.system("tor --RunAsDaemon 1 --ControlPort 9051 --SocksPort 9050")
        time.sleep(6.66)
        
        # 3. Verify resurrection
        try:
            with Controller.from_port(port=9051) as ctrl:
                ctrl.authenticate()
                log.warning("⚡ TOR RESURRECTION SUCCESSFUL ⚡")
        except:
            log.error("🔥 TOR RESURRECTION FAILED! USING DIRECT CONNECTION")

    def _normalize_proxy(self, proxy):
        """Ensure all proxies emerge from the void properly formatted"""
        if "://" not in proxy:
            # Randomly bless with HTTP or SOCKS5 (66.6% chance for HTTP)
            return f"http://{proxy}" if random.random() < 0.666 else f"socks5://{proxy}"
        return proxy

    def get_random_proxy(self, quantum_entangled=False):
        """Retrieve a random proxy blessed by the abyss"""
        # 13% chance for violent TOR rotation
        if random.random() < 0.13:
            self.rotate_tor(violent=True)
        
        """Retrieve a normalized proxy blessed by the void"""
        proxy = random.choice(self.proxy_list or [""])
        proxy = self._normalize_proxy(proxy)  # Ensure proper format
        
        if quantum_entangled:
            return f"quantum://{proxy.split('://')[-1]}?entropy={os.urandom(4).hex()}"

        # Standard selection with death checks
        while True:
            if not self.proxy_list:  # Fallback to TOR
                return f"socks5://127.0.0.1:{random.choice(TOR_PORTS)}"
            
            proxy = random.choice(self.proxy_list)
            
            # Check proxy health in parallel
            future = self.executor.submit(self._test_proxy_virility, proxy)
            if future.result(timeout=3) is True:
                return proxy
            
            # Move failed proxy to graveyard
            self.proxy_graveyard.add(proxy)
            self.proxy_list.remove(proxy)
            
            # Every 13 failures, attempt resurrection
            MAX_GRAVEYARD_SIZE = 666  # Prevent memory bloat
            if len(self.proxy_graveyard) > MAX_GRAVEYARD_SIZE:
                oldest = sorted(self.proxy_graveyard)[:13]
                self.proxy_graveyard -= set(oldest)

    def _attempt_graveyard_resurrection(self):
        """Raise the dead in unholy batches of 13"""
        zombies = []
        for proxy in sorted(self.proxy_graveyard)[:13]:  # Oldest first
            try:
                if self._test_proxy_virility(proxy):
                    zombies.append(proxy)
                    self.proxy_graveyard.remove(proxy)
                    log.warning(f"⚡ ZOMBIE PROXY RISES: {proxy} ⚡")
            except:
                continue
        
        if zombies:
            self.proxy_list.extend(zombies)
            # Summon entropy storms
            os.system("dd if=/dev/urandom of=/dev/null count=666 &")

# ====== ETERNAL PROXY SINGLETON ====== #
PROXY_HANDLER = InfernalProxies()