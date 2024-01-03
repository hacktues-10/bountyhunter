import json
import pathlib
import time
from collections import OrderedDict

import click
import requests
from googleapiclient.discovery import build
from google.oauth2.service_account import Credentials
from jwt import JWT, jwk_from_pem

OAUTH_SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']
SECRETS_PATH = pathlib.Path('./secrets_dontleak_pls')


def get_default_google_key_file():
    filepath = next((SECRETS_PATH / 'google_keys').glob('*.json'))
    click.echo('Using google key file: %s' % filepath)
    return filepath


_config = None


def get_config():
    global _config
    if _config is None:
        with open(SECRETS_PATH / 'config.json', 'r') as file:
            _config = json.load(file)
    return _config


def get_default_spreadsheet_id():
    config = get_config()
    click.echo('Using spreadsheet id: %s' % config['spreadsheet_id'])
    return config['spreadsheet_id']


def get_default_github_app_id():
    config = get_config()
    click.echo('Using github app id: %s' % config['github']['app_id'])
    return config['github']['app_id']


def get_reports(sheet, spreadsheet_id):
    return sheet.values().get(spreadsheetId=spreadsheet_id, range='A:M').execute().get('values', [])


def get_name_from_email(email):
    before_at, _ = email.split('@')
    name = before_at.split('.')[0].title()
    if name.lower().replace(' ', '') == 'hacktues':
        name = 'Hack TUES 10 Team'
    return name


def generate_report_title(report, report_idx):
    if report['За какво пишеш?'] == 'Бъг':
        title = report['Какъв е бъгът?']
    else:
        title = report['Какво?']
    if len(title) > 69:
        title = title[:69] + '...'
    return f'Bounty #{report_idx}: {title}'


def get_google_drive_file_id_from_url(url):
    if 'id=' in url:
        return url.split('id=')[1].split('&')[0]
    elif 'file/d/' in url:
        return url.split('file/d/')[1].split('/')[0]
    else:
        raise ValueError(f'Invalid google drive url {url}')


def get_google_drive_download_link(file_id):
    return f'https://drive.google.com/uc?export=download&id={file_id}'


def generate_report_body(report):
    body = ''
    ignore_fields = []

    if 'Имейл адрес' in report:
        body += f"**От:** {get_name_from_email(report['Имейл адрес'])}\n"
        ignore_fields.append('Имейл адрес')

    if 'Клеймо за време' in report:
        body += f"**В:** {report['Клеймо за време']}\n"
        ignore_fields.append('Клеймо за време')

    if 'За какво пишеш?' in report:
        body += f"**За какво пишеш?** {report['За какво пишеш?']}\n"
        ignore_fields.append('За какво пишеш?')

    BUG_REPORT_LIST_FIELDS = [
        'Къде е?',
        'Устройство?',
        'Операционна система',
        'Браузър',
    ]

    if report['За какво пишеш?'] == 'Нова функция / предложение':
        BUG_REPORT_FIELDS = [
            'Какъв е бъгът?',
            *BUG_REPORT_LIST_FIELDS,
            'Как може да репликираме случая? (как се е случило - стъпки)',
            'Снимки или видеа - къде е, какво е и т.н.',
        ]
        for field in BUG_REPORT_FIELDS:
            if field in report:
                ignore_fields.append(field)
    else:
        ENHANCEMENT_REPORT_FIELDS = [
            'Къде?',
            'Снимки (до 10), ако е приложимо',
        ]
        for field in ENHANCEMENT_REPORT_FIELDS:
            if field in report:
                ignore_fields.append(field)
        for field in BUG_REPORT_LIST_FIELDS:
            if field in report:
                if not report['Какъв е бъгът?'].endswith('\n'):
                    report['Какъв е бъгът?'] += '\n'
                report['Какъв е бъгът?'] += f'- **{field}:** _{report[field].strip()}_\n'
                ignore_fields.append(field)

    IMAGE_FIELDS = [
        'Снимки (до 10), ако е приложимо',
        'Снимки или видеа - къде е, какво е и т.н.',
    ]
    for field in IMAGE_FIELDS:
        if field in report:
            if not report[field].strip():
                ignore_fields.append(field)
                continue
            field_value, report[field] = report[field], ''
            for i, url in enumerate(field_value.split(',')):
                report[field] += f'![{i}]({get_google_drive_download_link(get_google_drive_file_id_from_url(url))})\n'

    for title, content in report.items():
        if title in ignore_fields:
            continue
        body += f'# {title}\n{content}\n\n'
    return body


def get_default_github_app_private_key_path():
    config = get_config()
    click.echo('Using github app private key path: %s' % config['github']['private_key_path'])
    return config['github']['private_key_path']


def get_default_github_repo():
    config = get_config()
    click.echo('Using github repo: %s' % config['github']['repo'])
    return config['github']['repo']


def get_reports_as_dicts(sheet, spreadsheet_id):
    values = get_reports(sheet, spreadsheet_id)
    return [OrderedDict(zip(values[0], row)) for row in values[1:]]


def generate_github_app_jwt(app_id, private_key_path):
    with open(private_key_path, 'rb') as private_key_file:
        signing_key = jwk_from_pem(private_key_file.read())
    jwt = JWT()
    payload = {
        'iat': int(time.time()),
        'exp': int(time.time()) + (10 * 60),
        'iss': app_id
    }
    return jwt.encode(payload, signing_key, alg='RS256')


GITHUB_API_BASE_URL = 'https://api.github.com'


def get_github_api_headers(bearer_token):
    return {
        'Authorization': f'Bearer {bearer_token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }


def get_github_installation_id(jwt, github_repo):
    org, _ = github_repo.split('/')
    response = requests.get(f'{GITHUB_API_BASE_URL}/orgs/{org}/installation', headers=get_github_api_headers(jwt))
    installation = response.json()
    return installation['id']


def get_github_access_token(jwt, installation_id):
    response = requests.post(f'{GITHUB_API_BASE_URL}/app/installations/{installation_id}/access_tokens', headers=get_github_api_headers(jwt))
    token = response.json()
    return token['token']


def get_github_bounty_issues(access_token, repo):
    response = requests.get(f'{GITHUB_API_BASE_URL}/repos/{repo}/issues',
                            params={'labels': 'bounty'},
                            headers=get_github_api_headers(access_token))
    return response.json()


def get_issued_report_indexes(github_issues):
    return [int(issue['title'].split('#')[1].split(': ')[0])
            for issue in github_issues
            if issue['title'].startswith('Bounty #')]


def create_github_issue(repo, access_token, title, body, labels):
    response = requests.post(f'{GITHUB_API_BASE_URL}/repos/{repo}/issues',
                             headers=get_github_api_headers(access_token),
                             json={'title': title, 'body': body, 'labels': labels})
    return response.json()


@click.command()
@click.option('--google_key_file', default=get_default_google_key_file, help='Google key file')
@click.option('--spreadsheet_id', default=get_default_spreadsheet_id, help='Google spreadsheet id')
@click.option('--github_app_id', default=get_default_github_app_id, help='Github app id')
@click.option('--github_app_private_key_path', default=get_default_github_app_private_key_path, help='Github app private key path')
@click.option('--github_repo', default=get_default_github_repo, help='Github repo')
def main(google_key_file, spreadsheet_id, github_app_id, github_app_private_key_path, github_repo):
    credentials = Credentials.from_service_account_file(google_key_file, scopes=OAUTH_SCOPES)
    sheet = build('sheets', 'v4', credentials=credentials).spreadsheets()
    reports = get_reports_as_dicts(sheet, spreadsheet_id)

    github_jwt = generate_github_app_jwt(github_app_id, github_app_private_key_path)
    installation_id = get_github_installation_id(github_jwt, github_repo)
    access_token = get_github_access_token(github_jwt, installation_id)
    issues = get_github_bounty_issues(access_token, github_repo)
    issued_report_indexes = get_issued_report_indexes(issues)

    newly_issued_reports = []
    dismissed_reports = []
    for report_idx, report in enumerate(reports):
        if report_idx in issued_report_indexes:
            dismissed_reports.append(report_idx)
            continue
        title = generate_report_title(report, report_idx)
        body = generate_report_body(report)
        if report['За какво пишеш?'] == 'Нова функция / предложение':
            category_label = 'enhancement'
        else:
            category_label = 'bug'
        issue = create_github_issue(github_repo, access_token, title, body, ['bounty', category_label])
        newly_issued_reports.append(report_idx)
        click.echo('Created issue: %s' % issue['id'])

    click.echo('Newly issued: %d' % len(newly_issued_reports))
    click.echo('Already existing: %d' % len(dismissed_reports))
        

if __name__ == '__main__':
    main()