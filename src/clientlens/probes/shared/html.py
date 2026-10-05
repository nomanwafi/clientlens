"""HTML parsing helpers shared by marketing and security probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag


@dataclass
class HtmlSnapshot:
    """Parsed view of a fetched HTML document."""

    url: str
    final_url: str
    soup: BeautifulSoup
    raw: str
    base_url: str = ""

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = self.final_url or self.url

    # ---- document-level accessors -------------------------------------------
    @property
    def title(self) -> str:
        if self.soup.title and self.soup.title.string:
            return self.soup.title.string.strip()
        return ""

    def meta(self, name: str = "", prop: str = "", http_equiv: str = "") -> str:
        for attrs, _key in (
            ({"name": name}, name),
            ({"property": prop}, prop),
            ({"http-equiv": http_equiv}, http_equiv),
        ):
            attrs = {k: v for k, v in attrs.items() if v}
            if not attrs:
                continue
            tag = self.soup.find("meta", attrs=attrs)
            if tag and tag.get("content"):
                return str(tag["content"]).strip()
        return ""

    def meta_all(self, **attrs: str) -> list[tuple[str, str]]:
        """Return every ``<meta>`` matching the given attribute, as (name, content)."""
        clean = {k.replace("_", "-"): v for k, v in attrs.items() if v}
        out: list[tuple[str, str]] = []
        for tag in self.soup.find_all("meta", attrs=clean):
            key = tag.get("name") or tag.get("property") or tag.get("http-equiv") or ""
            content = tag.get("content") or ""
            out.append((str(key), str(content)))
        return out

    def links(self, *, same_host_only: bool | None = None) -> list[str]:
        host = urlparse(self.base_url).hostname or ""
        seen: list[str] = []
        for a in self.soup.find_all("a", href=True):
            href = str(a["href"]).strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            absolute = urljoin(self.base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in {"http", "https"}:
                continue
            if same_host_only is True and parsed.hostname != host:
                continue
            if same_host_only is False and parsed.hostname == host:
                continue
            seen.append(absolute.split("#")[0])
        # stable de-dup preserving order
        return list(dict.fromkeys(seen))

    def scripts(self) -> list[str]:
        out: list[str] = []
        for tag in self.soup.find_all("script", src=True):
            out.append(urljoin(self.base_url, str(tag["src"])))
        return out

    def inline_scripts(self) -> list[str]:
        out: list[str] = []
        for tag in self.soup.find_all("script"):
            if not tag.get("src") and tag.string:
                out.append(str(tag.string))
        return out

    def stylesheets(self) -> list[str]:
        out: list[str] = []
        for tag in self.soup.find_all("link", rel="stylesheet"):
            href = tag.get("href")
            if href:
                out.append(urljoin(self.base_url, str(href)))
        return out

    def images(self) -> list[str]:
        out: list[str] = []
        for tag in self.soup.find_all("img", src=True):
            out.append(urljoin(self.base_url, str(tag["src"])))
        return out

    def json_ld_blocks(self) -> list[str]:
        out: list[str] = []
        for tag in self.soup.find_all("script", type="application/ld+json"):
            if tag.string:
                out.append(str(tag.string))
        return out

    def find_all_text(self, selector: str) -> list[Tag]:
        return list(self.soup.select(selector))

    def first_html(self, selector: str, limit: int = 500) -> str:
        tag = self.soup.select_one(selector)
        return str(tag)[:limit] if tag else ""


def parse_html(url: str, final_url: str, body: str) -> HtmlSnapshot:
    soup = BeautifulSoup(body, "lxml")
    return HtmlSnapshot(url=url, final_url=final_url, soup=soup, raw=body)


def text_of(tag: Tag | None) -> str:
    return tag.get_text(strip=True) if tag else ""


@dataclass
class LinkInventory:
    """Counts + samples of a document's outbound links."""

    total: int = 0
    internal: list[str] = field(default_factory=list)
    external: list[str] = field(default_factory=list)
    nofollow: list[str] = field(default_factory=list)

    @property
    def external_ratio(self) -> float:
        return len(self.external) / self.total if self.total else 0.0


def build_link_inventory(html: HtmlSnapshot, sample_limit: int = 200) -> LinkInventory:
    inv = LinkInventory()
    internal = html.links(same_host_only=True)
    external = html.links(same_host_only=False)
    inv.internal = internal[:sample_limit]
    inv.external = external[:sample_limit]
    inv.total = len(internal) + len(external)

    for a in html.soup.find_all("a", href=True):
        rel = " ".join(a.get("rel") or []).lower()
        if "nofollow" in rel:
            href = urljoin(html.base_url, str(a["href"]))
            inv.nofollow.append(href.split("#")[0])
    inv.nofollow = list(dict.fromkeys(inv.nofollow))[:sample_limit]
    return inv
