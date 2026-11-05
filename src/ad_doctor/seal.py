"""Passphrase encryption of a viewer file (`ad-doctor view`, on by default with a graph).

The page's payload (the gzip-compressed viewmodel) is encrypted with AES-256-GCM under a
key derived from the passphrase with PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP's
2023 figure for SHA-256), a random 16-byte salt and a random 12-byte nonce. The page
decrypts it with WebCrypto after the reader types the passphrase. What stays readable
before unlock: the ad-doctor version, the build time, the KDF and cipher parameters, and
the SHA-256 of the ciphertext. The version, build time and parameters are the GCM
additional data, so editing them makes decryption fail. The SHA-256 is not (it is the
hash of the ciphertext itself): the page computes it from the data in the file, shows
that, and refuses to unlock when it differs from the recorded one. The size shown is
measured by the page too. The domain, every name and every finding are inside the
ciphertext, and the GCM tag authenticates all of it.

The passphrase comes from a prompt or the AD_DOCTOR_VIEW_PASSPHRASE environment variable
and is never written anywhere.
"""

from __future__ import annotations

import base64
import hashlib
import math
import secrets
import unicodedata
from typing import Any

from Crypto.Cipher import AES

ENV = "AD_DOCTOR_VIEW_PASSPHRASE"
ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
MIN_LENGTH = 14
MIN_DISTINCT = 6
SUGGESTED_WORDS = 7

# 512 short, common, unambiguous English words: a suggested passphrase of seven of them
# carries 63 bits of entropy (log2(512) = 9 bits a word), before the 600k PBKDF2 rounds.
_WORDLIST = """
acorn acre adapt adobe agent agile alarm album alley alpine amber ample anchor
angle ankle antler apple apron arena argue aroma arrow aspen attic audio avenue
awake badge bagel bakery ballad balmy bamboo banjo barge basil basin beach beacon
beard beret berry bison blade blank blaze blend bloom blues board boast bonus
booth bound brain brave bread bride brief brisk broom brush bugle cabin cable
cadet camel canal candy canoe canon cargo carol cedar chalk charm chart chess
chief chili chime cider cinema civic claim clamp clay clerk cloak clock cloud
clove coach cobra comet coral couch cove crane crate crawl cream crest crisp
crown crumb cubic curve cycle dance delta depot diary digit diner disco ditch
diver dock dodge dome donor dough draft drama dream drift drill drum dune
eagle easel ebony elbow elder ember empty enjoy entry envoy epoch equal essay
ethic event exact extra fable facet fairy faith fancy feast fence ferry fever
fiber field fiery final flame flask fleet float flock flora flute focal foggy
forge forum fossil frame fresh frost fudge gable galaxy gauge gecko genre ghost
giant ginger glade glass glide globe glove goose gorge grain grape graph grass
gravy great grill grove guard guest guide guild happy harbor hasty hatch hazel
heart hedge heron hinge hobby hoop hotel house humid husky hymn igloo image
index inlet input island ivory jacket jelly jewel jolly judge juice jumbo jungle
karma kayak khaki kiosk kitten knack knee koala label ladle lager lake lance
laser latch lemon level lilac lily linen llama lobby local lodge lofty logic
lotus lucky lunar macro magic maize major mango maple march marsh mason medal
melon merit metal meter micro mild mimic mirth mocha model molar money moose
moral motor motto mound mouse movie mural music nectar needle nerve nest noble
north notch novel nudge nylon oasis ocean olive omega opera orbit orchid organ
otter outer oxide ozone paddle pagoda palm panda paper parade parka pasta patio
peach pearl pecan pedal penny pepper perch piano picnic pilot pinch pixel pizza
plaid plain plank plume plush poem polar pond poppy porch prairie prism prize
proud pulse quail quart quartz queen quest quiet quilt quota radio rainy range
rapid raven razor ready realm recap relay relic remix rhyme ridge rinse ripple
river roast robin robot rocket rodeo roomy rotor rouge round route rover ruby
rugby ruler rumba rural saddle safari saga salad salmon salsa sandy satin sauce
scale scarf scene scout scrub sedan seed shark sheep shelf shine shore shrub
siren skate sketch skier slate sleek smile smoky snack snail solar sonic spark
spice spine spoon sport spray stack stage stamp steam steel stern stone storm
stove straw strum sugar sunny super swamp swift syrup table tango tapir teapot
tenor thorn tiger token topaz torch tower train tundra tuner turtle tutor tweed
twig ultra umber uncle union unity urban usher valid valley valve vapor vault
velvet venue vessel video vigor vinyl viola violet vital vivid vocal voter wagon
waltz water whale wheat whisk widget willow window wombat wool yacht yeast yodel
young zesty zinc zippy zone
"""
WORDS = tuple(_WORDLIST.split())


class PassphraseError(ValueError):
    pass


def normalize(passphrase: str) -> str:
    """NFC, as the page does, so the same typed text gives the same key everywhere."""
    return unicodedata.normalize("NFC", passphrase)


def problem(passphrase: str) -> str | None:
    """Why a passphrase is refused, or None. Length is what counts against an offline
    guesser; a minimum of distinct characters stops 'aaaaaaaaaaaaaa'."""
    text = normalize(passphrase)
    if len(text) < MIN_LENGTH:
        return f"is shorter than {MIN_LENGTH} characters"
    if len(set(text)) < MIN_DISTINCT:
        return f"uses fewer than {MIN_DISTINCT} different characters"
    return None


def suggest(words: int = SUGGESTED_WORDS) -> str:
    """A diceware-style passphrase from the system's CSPRNG."""
    return "-".join(secrets.choice(WORDS) for _ in range(words))


def suggestion_bits(words: int = SUGGESTED_WORDS) -> int:
    return int(words * math.log2(len(WORDS)))


def additional_data(header: dict[str, Any]) -> bytes:
    """The header fields bound to the ciphertext (not the size or the SHA-256, which the
    page measures itself). The page builds the same string from the same fields."""
    parts = [
        "ad-doctor-view",
        str(header["schema"]),
        header["version"],
        header["built_at"],
        str(header["kdf"]["iterations"]),
        header["kdf"]["salt"],
        header["cipher"]["nonce"],
    ]
    return "|".join(parts).encode()


def _key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", normalize(passphrase).encode(), salt, iterations, 32)


def seal(plain: bytes, passphrase: str, header: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """Encrypt `plain`; return the ciphertext (with the GCM tag appended, as WebCrypto
    expects it) and `header` completed with the KDF and cipher parameters."""
    why = problem(passphrase)
    if why is not None:
        raise PassphraseError(f"the passphrase {why}")
    salt, nonce = secrets.token_bytes(SALT_BYTES), secrets.token_bytes(NONCE_BYTES)
    header = {
        **header,
        "kdf": {
            "name": "PBKDF2-HMAC-SHA256",
            "iterations": ITERATIONS,
            "salt": base64.b64encode(salt).decode(),
        },
        "cipher": {"name": "AES-256-GCM", "nonce": base64.b64encode(nonce).decode()},
    }
    key = _key(passphrase, salt, ITERATIONS)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
    cipher.update(additional_data(header))
    body, tag = cipher.encrypt_and_digest(plain)
    return body + tag, header


def unseal(data: bytes, passphrase: str, header: dict[str, Any]) -> bytes:
    """The inverse of seal(); raises ValueError on a wrong passphrase or edited data."""
    salt = base64.b64decode(header["kdf"]["salt"])
    nonce = base64.b64decode(header["cipher"]["nonce"])
    key = _key(passphrase, salt, int(header["kdf"]["iterations"]))
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
    cipher.update(additional_data(header))
    return cipher.decrypt_and_verify(data[:-TAG_BYTES], data[-TAG_BYTES:])
