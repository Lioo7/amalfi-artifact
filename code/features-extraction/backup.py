def total_search(root_node):
    #(value, group ID, found or not, sub group ID: -1 is stand alone, other values are sub group ID)
    full_data = [['screenshot',1,0,-1],['keypress',1,0,1],['POST',1,0,1],
    ['creditcard',1,0,-1],['cookies',1,0,-1],['passwords',1,0,-1],['appData',1,0,-1],['read',2,0,-1],
    ['write',2,0,-1],['file',2,0,-1],['require["fs"]',2,0,-1],['exec',3,0,-1],['spawn',3,0,-1],
    ['fork',3,0,-1],['thread',3,0,-1],['process',3,0,-1],['child_process',3,0,-1],['send',4,0,-1],
    ['export',4,0,-1],['upload',4,0,-1],['post',4,0,-1],['XMLHttpRequest',4,0,-1],['submit',4,0,-1],
    ['crypto',5,0,-1],['mining',5,0,-1],['encodeURIComponent',6,0,-1],['querystring',6,0,-1],
    ['qs',6,0,-1],['base64',6,0,-1],['btoa',6,0,-1],['atob',6,0,-1],['Buffer',6,0,-1],
    ['JSON.stringify',6,0,-1],['eval',7,0,-1],['Function',7,0,-1],
    ['preinstall',8,0,-1],['postinstall',8,0,-1],['npm install',8,0,-1]]

    logging.info("start func: total_seatch")
    search_keyword_in_code(root_node, full_data)
    result = {}
    for item in full_data:
        key = item[-1]
        if key not in result:
            result[key] = []
        result[key].append(item)
    full_data = list(result.values())
    is_using = [0,0,0,0,0,0,0,0]
    for item in full_data:
        if item[0][3] == -1:
            for inner_item in item:
                if inner_item[2] == 1:
                    is_using[inner_item[1] - 1] = 1
        else:
            for inner_item in item:
                if inner_item[2] == 0:
                    break
                is_using[inner_item[1] - 1] = 1
    return is_using
  
    
def search_minified_code(directory_path) -> Literal[1, 0]:
    """
    5
    Presence of minified code (to avoid detection) or binary files (such as binary executables)
    """
    logging.info("start func: search_minified_code")
    is_minified = extract_is_minified_feature(directory_path)
    
    return is_minified


def gather_data(root_dir,trigger):
    all_list = []
    if trigger:
        all_list.append(['package','version','PII','file_sys_access','file_process_creation',
        'network_access','Cryptographic_functionality', 'data_encoding',
        'dynamic_code_generation','package_installation','label'])
    for folder in os.listdir(root_dir):

        folder_path = os.path.join(root_dir, folder)
        #print(f"{folder}, {folder_path}\n")

        if os.path.isdir(folder_path):
            file_name = os.path.basename(folder_path)
            current_file_values = file_name.split('-v-')
            current_list = []
            current_list.append(current_file_values[0])
            current_list.append(current_file_values[1])
            for i in range(0,8):
                current_list.append(0)
            label = "benign" if trigger else "malicious"
            current_list.append(label)
            print("-----------------------------------------------")
            print(current_list)
            for dirpath, dirnames, filenames in os.walk(folder_path):
                for fi in filenames:
                    print(fi)
                    local_list = []
                    if fi.endswith(".js"):
                        path_to_go = dirpath +"\\" + fi
                        try:
                            local_list = local_list + total_search(parse_file(path_to_go))
                        except:
                            local_list = local_list + [0,0,0,0,0,0,0,0]

                    for i in range(0, len(local_list)):
                        if current_list[i+2] == 0:
                            current_list[i+2] = local_list[i]
            
            all_list.append(current_list)
    return all_list


def search_keyword_in_code(root_node, keywords):
  """
  TODO:
  * current situation: the function stoping after the function find the first match
  * what to improve: have to add the function the ability to count the number of occurrences of all keywords
  """
  logging.info(f"start func: search_keyword_in_code")
  
  for child in root_node.children:
    # search if the child in one of the keywords
    logging.debug(f"child: {child.text.decode()}")
    for tpl in keywords:
      if child.text.decode() == tpl[0]:
          #found = True
          tpl[2] = 1
          logging.info(f"keyword found!\nThe keyword that found is: {child.text.decode()}")
          #break

    logging.debug("calling recursion")
    search_keyword_in_code(child, keywords)

  return keywords