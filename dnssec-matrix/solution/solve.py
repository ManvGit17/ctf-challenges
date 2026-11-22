import hashlib
import sys
import requests


def sha1_iter(base, salt, iters):
  curr = (base + salt).encode()
  for _ in range(iters):
    curr = hashlib.sha1(curr).digest()
  return curr.hex()


def main():
  host = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8080'
  base_url = host.rstrip('/') + '/api/query'

  print('[*] Step 0: Querying start.matrix.ctf')
  try:
    r = requests.post(
        base_url, json={'domain': 'start.matrix.ctf', 'qtype': 'TXT'}
    )
    data = r.json()
    if not data.get('answer'):
      print(f'[-] Unexpected response: {data}')
      return
    print(f"    -> {data['answer'][0]}")
  except Exception as e:
    print(f'Error: {e}')
    return

  current_node = 'start'

  for step in range(5):
    query_name = f'dummy.wild.{current_node}.matrix.ctf'
    print(
        f'\n[*] Step {step+1}: Querying wildcard for NXDOMAIN NSEC3 leak ->'
        f' {query_name}'
    )

    try:
      r = requests.post(base_url, json={'domain': query_name, 'qtype': 'A'})
      data = r.json()

      if data['status'] != 'NXDOMAIN':
        print('    -> Did not get NXDOMAIN! Failed.')
        return

      if not data.get('authority'):
        print('    -> No authority section returned.')
        return

      auth = data['authority'][0]
      iterations = auth['iterations']
      salt = auth['diagnostic_hint_salt']

      print(
          f"    -> Extracted NSEC3 details: Iterations={iterations},"
          f" Salt='{salt}'"
      )

      next_node = sha1_iter(current_node, salt, iterations)
      print(f'    -> Computed next node: {next_node}')

      current_node = next_node
    except Exception as e:
      print(f'Error: {e}')
      return

  print(f'\n[*] Final Step: Fetching Flag from {current_node}.matrix.ctf')
  try:
    r = requests.post(
        base_url, json={'domain': f'{current_node}.matrix.ctf', 'qtype': 'TXT'}
    )
    data = r.json()
    if data.get('answer'):
      print(f"    -> FLAG: {data['answer'][0]}")
    else:
      print(f'[-] No answer returned: {data}')
  except Exception as e:
    print(f'Error fetching flag: {e}')


if __name__ == '__main__':
  main()
