########################################
#             Made by Duo              #
#         generate dot file            #
########################################
import pydot

########################################
#           input                      #
########################################
FILE_NAME = 'kernelfunction'
FILE = FILE_NAME+'.txt'
# TARGET_KEY = 'task_clear_jobctl_trapping()(0)'
TARGET_KEY = 'CMD2a(0)'


log_list = []
log_count_dict = {}
log_tree = {}
s_path = []
#########################################
#         entry point function          #
#########################################
syscall_list = ['do_syscall_fsync()(0)','SyS_fsync()(0)','sys_fdatasync()(0)','sys_fsync()(0)']
cmd_list = ['CMD35(0)','CMD2a(0)','CMD2a(1)','CMD2a(2)']
# cmd_list = ['CMD35(0)']

#########################################
#        identify caller-callee         #
#########################################
def if_go_deeper(ptr):
	return True if '{' in ptr else False

def if_go_back(ptr):
	return True if '}' in ptr else False

def if_stay(ptr):
	return True if ';' in ptr else False

##########################################
#            Draw graph with colors      #
##########################################
def draw(parent_name, child_name):
	if parent_name in syscall_list:
		node_a = pydot.Node(parent_name, style="filled",fillcolor="green", shape='box', fontsize='9', margin=0, fixedsize=True)
	else: 
		node_a = pydot.Node(parent_name, shape='box', fontsize='8', margin=0, fixedsize=True)
	# if child_name in cmd_list:
	if 'CMD' in child_name:
		node_b = pydot.Node(child_name, style="filled",fillcolor="blue", shape='box', fontsize='12', fontcolor='white', margin=0, fixedsize=True)
	else: 
		node_b = pydot.Node(child_name, shape='box', fontsize='8', margin=0, fixedsize=True)
	graph.add_node(node_a)
	graph.add_node(node_b)
	if parent_name in s_path_all and child_name in s_path_all:
		edge = pydot.Edge(node_a, node_b, color='red', penwidth= 5) 
	else:
		edge = pydot.Edge(node_a, node_b) 
	graph.add_edge(edge)

def draw_s_path(parent_name, child_name):
	if parent_name and child_name in s_path_all:
		if parent_name in syscall_list:
			node_a = pydot.Node(parent_name, style="filled",fillcolor="green", shape='box', fontsize='20')
		else: 
			node_a = pydot.Node(parent_name, shape='box')
		if child_name in cmd_list:
			node_b = pydot.Node(child_name, style="filled",fillcolor="blue",  fontsize='20',fontcolor='white',shape='box')
		else: 
			node_b = pydot.Node(child_name, shape='box')
		graph.add_node(node_a)
		graph.add_node(node_b)
		if parent_name in s_path_all and child_name in s_path_all:
			edge = pydot.Edge(node_a, node_b, color='red', penwidth= 2) 
		else:
			edge = pydot.Edge(node_a, node_b) 
		graph.add_edge(edge)

# def draw(parent_name, child_name):
# 	if parent_name in syscall_list or child_name in cmd_list:
# 		edge = pydot.Edge(parent_name, child_name)   
# 		graph.add_edge(edge)

############################################
#                generate paths            #
############################################
def visit(node, parent=None):
    for k,v in node.items():
        if isinstance(v, dict):
            # We start with the root node whose parent is None
            # we don't want to graph the None node
            if parent:
                draw(parent, k)
            visit(v, k)
        else:
            draw(parent, k)
            # drawing the label using a distinct name
            draw(k, k+'_'+v)

def visit_s_p(node, parent=None):
    for k,v in node.items():
        if isinstance(v, dict):
            # We start with the root node whose parent is None
            # we don't want to graph the None node
            if parent:
                draw_s_path(parent, k)
            visit(v, k)
        else:
            draw_s_path(parent, k)
            # drawing the label using a distinct name
            draw_s_path(k, k+'_'+v)

def build_list(file_name):
	with open(file_name) as f:
		for log in f:
			log = log.strip().split(" ")[0]
			if ';' in log:
				log = log[0:-1]
			if log not in log_list:
				log_list.append(log)

def build_count_dict(file_name):
	build_list(file_name)
	for log in log_list:
		log_count_dict[log] = 0
##################################################
#               create the dictionary tree       #
##################################################
def build_tree(file_name):
	tree_raw = open(file_name)
	depth_list = []
	current_depth = log_tree
	for log in tree_raw:
		log_raw = log
		log = log.strip().split(" ")[0]
		if(if_go_deeper(log_raw)):
			previous_log = log
			current_depth = current_depth.setdefault(log+'('+str(log_count_dict[log])+')',{})
			depth_list.append(log+'('+str(log_count_dict[log])+')')
			log_count_dict[log]+=1
		elif(if_go_back(log_raw)):
			depth_list = depth_list[0:-1]
			depth_ = log_tree
			for depth in depth_list:
				depth_ = depth_[depth]
			current_depth = depth_
		elif(if_stay(log_raw)):
			log = log[0:-1]
			previous_depth_ = current_depth
			current_depth = current_depth.setdefault(log +'('+str(log_count_dict[log])+')',{})
			log_count_dict[log]+=1
			current_depth = previous_depth_

##################################################
#        identify paths with device commands      #
##################################################
def suspicious_path(d, k, path=None):
    if path is None:
        path = []
    # Reached bottom of dict - no good
    if not isinstance(d, dict):
        return False
    
    # Found it!
    if k in d.keys():
        path.append(k)
        return path
    
    else:
        check = list(d.keys())
        # Look in each key of dictionary
        while check:
            first = check[0]
            # Note which we just looked in
            path.append(first)
            if suspicious_path(d[first], k, path) is not False:
                break
            else:
                # Move on
                check.pop(0)
                path.pop(-1)
        else:
            return False
        return path

def node_count(file):
	count = 0
	with open(file) as f:
		for log in f:
			if '}' in log:
				pass
			else:
				count += 1
	return count

##########################################
#                 main                   #
##########################################
file = FILE
build_count_dict(file)
print("count dictionary finished")
build_tree(file)
print("build tree finished")
s_path_all = []
for target in cmd_list:
	try:
		s_path = suspicious_path(log_tree, target)
		s_path_all.extend(s_path)
	except TypeError:
		pass		
s_path_all = list(set(s_path_all))
compare_path = suspicious_path(log_tree, 'scsi_dispatch_cmd()(0)')
print("suspicious path found",s_path_all)
print(len(s_path_all), 'nodes in suspicious path VS totally', node_count(file), 'nodes')
suspicious_path(log_tree, 'scsi_dispatch_cmd()(0)')
print('Path to scsi_dispatch_cmd(): ', compare_path)
# print(len(compare_path), 'nodes in suspicious path VS tottotally', node_count(file), 'nodes')

##################################################
#               generated dot file               #
##################################################

graph = pydot.Dot(graph_type='digraph',nodesep=.05)
visit(log_tree)
graph.write_png(FILE_NAME+'.png')

graph_s_p = pydot.Dot(graph_type='digraph',nodesep=.05)
visit_s_p(log_tree)
graph_s_p.write_png(FILE_NAME+'_s_path.png')

