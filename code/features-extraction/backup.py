def gather_data(root_dir, trigger):
    all_list = []
    if trigger:
        all_list.append(['package', 'version', 'PII', 'file_sys_access', 'file_process_creation',
                          'network_access', 'Cryptographic_functionality', 'data_encoding',
                          'dynamic_code_generation', 'package_installation', 'label'])
    
    current_file_values = dirpath.split('-v-')
    current_list= []
    current_list.append(current_file_values[0])
    current_list.append(current_file_values[1])
    for dirpath, dirnames, filenames in os.walk(root_dir):
        #file_path = os.path.join(dirpath, file)
        print(dirnames)
        continue
        
        for i in range(0,8):
            current_list.append[0]
        label = "benign" if trigger else "malicious"
        current_list.append(label)
        for file in filenames:
            
            local_list = []
            if file.endswith(".js"):
                
                #print(f"{current_file_values}, {file_path}\n")
                
                local_list.append(search_PII(parse_file(file_path)))
                local_list.append(search_file_sys_access(parse_file(file_path)))
                local_list.append(search_file_process_creation(parse_file(file_path)))
                local_list.append(search_network_access(parse_file(file_path)))
                local_list.append(search_Cryptographic_functionality(parse_file(file_path)))
                local_list.append(search_data_encoding(parse_file(file_path)))
                local_list.append(search_dynamic_code_generation(parse_file(file_path)))
                local_list.append(search_package_installation(parse_file(file_path)))
                
                local_list.append(current_list)
            for i in range(0, len(local_list)):
                if current_list[i] == 0:
                    current_list[i] = local_list[i]

        
    return all_list










def gather_data(root_dir,trigger):
    all_list = []
    if trigger:
        all_list.append(['package','version','PII','file_sys_access','file_process_creation',
        'network_access','Cryptographic_functionality', 'data_encoding',
        'dynamic_code_generation','package_installation','label'])
    for folder in os.listdir(root_dir):

        folder_path = os.path.join(root_dir, folder)
        print(f"{folder}, {folder_path}\n")

        if os.path.isfolder(folder_path):
            print("yes")
            file_name = os.path.basename(folder_path)
            current_file_values = file_name.split('-v-')
            current_list = []
            current_list.append(current_file_values[0])
            current_list.append(current_file_values[1])
            for dirpath, dirnames, filenames in os.walk(folder_path):
                None
            current_list.append(search_PII(parse_file(folder_path)))
            current_list.append(search_file_sys_access(parse_file(folder_path)))
            current_list.append(search_file_process_creation(parse_file(folder_path)))
            current_list.append(search_network_access(parse_file(folder_path)))
            current_list.append(search_Cryptographic_functionality(parse_file(folder_path)))
            current_list.append(search_data_encoding(parse_file(folder_path)))
            current_list.append(search_dynamic_code_generation(parse_file(folder_path)))
            current_list.append(search_package_installation(parse_file(folder_path)))
            current_list.append(search_package_installation(parse_file(folder_path)))
            label = "benign" if trigger else "malicious"
            current_list.append(label)
            all_list.append(current_list)
    return all_list

if __name__ == '__main__':

    root_dir_benign =  "C:\\Users\\Amit\\AMIT\\cyberdetectiontaskfinal\\amalfi-artifact\data\\training_data\\benign"
    root_dir_malicious =  "C:\\Users\\Amit\\AMIT\\cyberdetectiontaskfinal\\amalfi-artifact\data\\training_data\\malicious"
    end_result = gather_data(root_dir_benign,True) + gather_data(root_dir_malicious,False)
    exit()
    full_path = "C:\\Users\\Amit\\AMIT\\cyberdetectiontaskfinal\\amalfi-artifact\\data\\dataset\\change-features.csv"
    with open(full_path, "w", newline="") as f:
        # Create a CSV writer object
        writer = csv.writer(f)

        # Write the data to the file
        for row in end_result:
            writer.writerow(row)

    '''print(f"search_PII: {search_PII(root_node)}")
    print(f"search_file_sys_access: {search_file_sys_access(root_node)}")
    print(f"search_file_process_creation: {search_file_process_creation(root_node)}")
    print(f"search_network_access: {search_network_access(root_node)}")
    print(f"search_Cryptographic_functionality: {search_Cryptographic_functionality(root_node)}")
    print(f"search_data_encoding: {search_data_encoding(root_node)}")
    print(f"search_dynamic_code_generation: {search_dynamic_code_generation(root_node)}")
    print(f"search_package_installation: {search_package_installation(root_node)}")
    #search_PII(root_node)'''
    #directory_path = ''
    #search_minified_code(directory_path)