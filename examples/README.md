# examples/ — রেডিমেড স্ক্রিপ্ট / Ready-made scripts

এখানে কিছু ব্যবহার-প্রস্তুত স্ক্রিপ্ট আছে। সরাসরি কপি করে ব্যবহার করা যায়।

---

## 1. `extract-findings.py` — রিপোর্ট থেকে কাজের তালিকা

JSON স্ক্যান ফাইল থেকে সমস্যাগুলো সাজিয়ে তালিকা বানায়। টিকিট, ইমেইল বা
spreadsheet-এ সরাসরি পেস্ট করা যায়।

```bash
# সব সমস্যা দেখো
python examples/extract-findings.py reports/acme.json

# শুধু confirmed সমস্যা
python examples/extract-findings.py reports/acme.json --confirmed-only

# Markdown ফরম্যাটে (GitHub issue/PR-এ পেস্ট করার জন্য)
python examples/extract-findings.py reports/acme.json --markdown > ticket.md
```

---

## 2. `monthly-scan.sh` — একসাথে অনেক সাইট স্ক্যান

ক্লায়েন্টদের সাইটের লিস্ট দিলে সব স্ক্যান করে, আগের স্ক্যানের সাথে তুলনা করে।

```bash
# ১) একটা ফাইল বানাও — প্রতি লাইনে একটা ডোমেইন
cat > clients.txt <<EOF
# আমার ক্লায়েন্টরা
example.com
shop.example.com
myclient.org
EOF

# ২) চালাও
chmod +x examples/monthly-scan.sh
./examples/monthly-scan.sh clients.txt
```

প্রতিটা সাইটের HTML/JSON রিপোর্ট `reports/` ফোল্ডারে জমা হবে।

---

## 3. `github-workflow.yml` — স্বয়ংক্রিয় সাপ্তাহিক স্ক্যান

GitHub Actions-এ বসালে প্রতি সপ্তাহে নিজে থেকে স্ক্যান হবে এবং সমস্যা পেলে
build fail করবে।

```bash
# ১) ফাইলটা কপি করো
mkdir -p .github/workflows
cp examples/github-workflow.yml .github/workflows/clientlens.yml

# ২) GitHub repo-র Settings → Secrets → Actions-এ যাও
#    CLIENTLENS_TARGET নামে একটা variable বানাও, value হিসেবে ডোমেইন দাও

# ৩) Commit + push করো — হয়ে গেছে!
```

> 💡 এটা শুধু **passive scan** চালায় (১-৫টা request) — production সাইটের জন্য নিরাপদ।

---

## নতুন স্ক্রিপ্ট যোগ করতে চাইলে

নতুন `.py` বা `.sh` ফাইল এখানে রেখে এই README-তে ব্যবহারের নিয়ম লিখে দাও।
