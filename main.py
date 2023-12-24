import os
from enum import Enum
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import gzip
import pickle
from bs4 import BeautifulSoup
import email
from email import header
import argparse
import base64


class Status(Enum):
    CLEAN = 0
    SPAM = 1


ENCODINGS = [  # supported by Python 3.6
    'ascii',
    'big5',
    'big5hkscs',
    'cp037',
    'cp273',
    'cp424',
    'cp437',
    'cp500',
    'cp720',
    'cp737',
    'cp775',
    'cp850',
    'cp852',
    'cp855',
    'cp856',
    'cp857',
    'cp858',
    'cp860',
    'cp861',
    'cp862',
    'cp863',
    'cp864',
    'cp865',
    'cp866',
    'cp869',
    'cp874',
    'cp875',
    'cp932',
    'cp949',
    'cp950',
    'cp1006',
    'cp1026',
    'cp1125',
    'cp1140',
    'cp1250',
    'cp1251',
    'cp1252',
    'cp1253',
    'cp1254',
    'cp1255',
    'cp1256',
    'cp1257',
    'cp1258',
    'cp65001',
    'euc_jp',
    'euc_jis_2004',
    'euc_jisx0213',
    'euc_kr',
    'gb2312',
    'gbk',
    'gb18030',
    'hz',
    'iso2022_jp',
    'iso2022_jp_1',
    'iso2022_jp_2',
    'iso2022_jp_2004',
    'iso2022_jp_3',
    'iso2022_jp_ext',
    'iso2022_kr',
    'latin_1',
    'iso8859_2',
    'iso8859_3',
    'iso8859_4',
    'iso8859_5',
    'iso8859_6',
    'iso8859_7',
    'iso8859_8',
    'iso8859_9',
    'iso8859_10',
    'iso8859_11',
    'iso8859_13',
    'iso8859_14',
    'iso8859_15',
    'iso8859_16',
    'johab',
    'koi8_r',
    'koi8_t',
    'koi8_u',
    'kz1048',
    'mac_cyrillic',
    'mac_greek',
    'mac_iceland',
    'mac_latin2',
    'mac_roman',
    'mac_turkish',
    'ptcp154',
    'shift_jis',
    'shift_jis_2004',
    'shift_jisx0213',
    'utf_32',
    'utf_32_be',
    'utf_32_le',
    'utf_16',
    'utf_16_be',
    'utf_16_le',
    'utf_7',
    'utf_8',
    'utf_8_sig'
]


class AntiSpam:
    @staticmethod
    def info(output_file):
        with open(output_file, 'w') as f:
            f.writelines([
                "SSOSM AntiSpam\n",
                "Mutu Gheorghita\n",
                "GRX\n",
                "1.0.0\n"
            ])

    @staticmethod
    def decode_text(text):
        for encoding in ENCODINGS:
            try:
                return text.decode(encoding=encoding)
            except Exception as e:
                pass
        return text.decode(encoding='utf-8', errors='replace')

    @staticmethod
    def extract_text_from_html(html, entry_path):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            decoded_body = soup.get_text(separator='\n', strip=True)
            # print(f"SOUP: {decoded_body} -> {entry_path}")
            return decoded_body
        except Exception as e:
            # print(f"SOUP ERROR: {e} -> {entry_path}")
            # print(f"SOUP ERROR: {decoded_body} -> {entry_path}")
            # decoded_body = bytes(decoded_body).decode(encoding="ISO-2022-JP", errors='replace')
            return html

    @staticmethod
    def decode_base64(content, entry_path):
        try:
            content = base64.b64decode(content).decode('utf-8')
        except Exception as e:
            # print(f"ERROR: {e} -> {entry_path}")
            pass
        return content

    @staticmethod
    def decode_email(content, entry_path):
        msg = email.message_from_string(content)

        # Decode and print headers
        for header_name, header_value in msg.items():
            # print(f'HEADER NAME: {header_name}')
            if header_name != "Subject":
                # print(f'HEADER NAME: {header_name}')
                # print(f'{entry_path}')
                continue

            decoded_header = header.decode_header(header_value)
            decoded_text = ""
            for text, encoding in decoded_header:
                try:
                    if encoding:
                        decoded_text += text.decode(encoding)
                    else:
                        decoded_text += text
                except Exception as e:
                    decoded_text = AntiSpam.decode_text(text)
            
            # print(f"{header_name}: {decoded_text} -> {entry_path}")
                    
        # Decode and print body
        if msg.is_multipart():
            bodies = []
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if "attachment" not in content_disposition:
                    body = part.get_payload(decode=True)
                    decoded_body = AntiSpam.decode_text(body)
                    decoded_body = AntiSpam.decode_base64(decoded_body, entry_path)  # email library does not always decode base64
                    if content_type == "text/html" or decoded_body.startswith('<'):
                        decoded_body = AntiSpam.extract_text_from_html(decoded_body, entry_path)
                    bodies.append(decoded_body)
            decoded_body = "\n".join(bodies)
        else:
            content_type = msg.get_content_type()
            body = msg.get_payload(decode=True)
            decoded_body = AntiSpam.decode_text(body)
            decoded_body = AntiSpam.decode_base64(decoded_body, entry_path)  # email library does not always decode base64
            if content_type == "text/html" or decoded_body.startswith('<'):
                decoded_body = AntiSpam.extract_text_from_html(decoded_body, entry_path)

        # print("\nBody:\n", decoded_body)
        return decoded_text, decoded_body

    @staticmethod
    def read_emails(path, status):
        data = list()

        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                entry_path = os.path.join(dirpath, filename)
                with open(entry_path, "rt", errors="ignore", encoding="utf-8") as fd:
                    content = fd.read()
                    
                    try: 
                        decoded_text, decoded_body = AntiSpam.decode_email(content, entry_path)
                        processed_content = decoded_text + "\n" + decoded_body
                    except Exception as e:
                        # print("ERROR: ", e)
                        # print(f"FAILED to process {decoded_text} -> {decoded_body}")
                        processed_content = content
                    
                    data.append((processed_content, status.value))

        print(f"Loaded {len(data)} emails from source {path}!")

        return data

    @staticmethod
    def load_data(cache_path, input_directory):
        data = []

        if os.path.exists(cache_path):
            with gzip.open(cache_path, "rb") as fd:
                data = pickle.load(fd)
        else:
            clean_data = AntiSpam.read_emails(f'{input_directory}/Clean', Status.CLEAN)
            spam_data = AntiSpam.read_emails(f'{input_directory}/Spam', Status.SPAM)

            data.extend(clean_data)
            data.extend(spam_data)

            with gzip.open(cache_path, "wb") as fd:
                pickle.dump(data, fd)

        print(f'Dataset size: {len(data)}!')
        
        return data

    @staticmethod
    def train(input_directory, cache_path, model_path):
        data = AntiSpam.load_data(cache_path, input_directory)
        emails, labels = zip(*data)
        
        vectorizer = TfidfVectorizer(
            input='content',
            sublinear_tf=True, 
            strip_accents="unicode",
            lowercase=True,
            encoding='utf-8', 
            decode_error='ignore', 
            stop_words='english', 
            analyzer='word',
            # max_df=0.01, 
            # max_df=0.8, 
            # min_df=3, 
            min_df=1, 
            norm='l2', 
            max_features=5000,
            token_pattern=r'\b\w+\b',
            # token_pattern=r'(?u)\b\w\w+\b',
            # ngram_range=(1, 1) # take a lot of memory.. 70GB or so for (1, 2)
        )

        emails = vectorizer.fit_transform(emails).toarray()

        rf = RandomForestClassifier(
            n_estimators=40000, 
            criterion='gini', 
            verbose=1, 
            n_jobs=24
        )
        rf.fit(emails, labels)

        with gzip.open(model_path, "wb") as fd:
            model = (vectorizer, rf)
            pickle.dump(model, fd)

    @staticmethod
    def test(input_folder, model_path):
        data = [
            *AntiSpam.read_emails(f"{input_folder}/clean", Status.CLEAN),
            *AntiSpam.read_emails(f"{input_folder}/spam", Status.SPAM)
        ]
        emails, labels = zip(*data)
        predictions = AntiSpam.predict(emails, model_path)
        correct_verdicts = sum(map(lambda x: x[0] == x[1], zip(labels, predictions)))

        print(f"Model accuracy {correct_verdicts / len(data)}%!")

    @staticmethod
    def predict(data, model_path):
        with gzip.open(model_path, "rb") as fd:
            tfidf, rf = pickle.load(fd)
            rf.verbose = 0  # disable verbose output
            data = tfidf.transform(data)
            predictions = rf.predict(data)
            return predictions

    @staticmethod
    def scan(input_folder, output_file, model_path):
        data = []
        files = []

        for entry in os.listdir(input_folder):
            email = os.path.join(input_folder, entry)
            with open(email, "rt", errors="ignore", encoding="utf-8") as fd:
                files.append(entry)

                content = fd.read()
                try: 
                    decoded_text, decoded_body = AntiSpam.decode_email(content, entry)
                    processed_content = decoded_text + "\n" + decoded_body
                except Exception as e:
                    # print("ERROR: ", e)
                    # print(f"FAILED to process {decoded_text} -> {decoded_body}")
                    processed_content = content

                data.append(processed_content)
        preds = AntiSpam.predict(data, model_path)

        verdicts = ["cln", "inf"]
        with open(output_file, "wt") as fd:
            for i, prediction in enumerate(preds):
                verdict = verdicts[prediction]
                fd.write(f'{files[i]}|{verdict}\n')


def main():
    parser = argparse.ArgumentParser(add_help=True, description="GRX AntiSpam Filter")
    parser.add_argument('-info', action='store', type=str, nargs=1, metavar='<output_file>',
                        help='Write project information to the output file.')
    parser.add_argument('-train', action='store', type=str, nargs=3, metavar=('<input_folder> <output_cache_file> <output_model_file>'),
                        help='Train the model with the data from the input folder.')
    parser.add_argument('-test', action='store', type=str, nargs=2, metavar=('<input_folder>', '<model_file>'),
                        help='Test the model with the data from the input folder.')
    parser.add_argument('-scan', action='store', type=str, nargs=3, metavar=('<folder>', '<output_file>', '<model_file>'),
                        help='Scan the folder and write the results to the output file.')

    args = parser.parse_args()
    
    if args.info:
        AntiSpam.info(output_file=args.info[0])
    elif args.scan:
        AntiSpam.scan(input_folder=args.scan[0], output_file=args.scan[1], model_path=args.scan[2]),
    elif args.train:
        AntiSpam.train(input_directory=args.train[0], cache_path=args.train[1], model_path=args.train[2])
    elif args.test:
        AntiSpam.test(input_folder=args.test[0], model_path=args.test[1])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc))
