import json
import sys
import os      

ASTEdge = ["AST"]
CFGEdge = ["CFG"]
PDGEdge = ["CDG","REACHING_DEF"]

class astNode:
    def __init__(self,id) -> None:
        self.id = id
        self.children = []
        self.parent = "-1"

    def addchild(self,id):
        self.children.append(id)

    def setparent(self,parent):
        assert self.parent == "-1"
        self.parent = parent

# 从原始JSON文件中获取节点信息
def getV(id,vertices):
    for vertice in vertices:
        if id == str(vertice["id"]['@value']) :
            return vertice

# 遍历并返回按顺序的完整AST
def traversalFull(id,nodes,vertices):
    rawnodejson = getV(id,vertices)
    nodejson = {}
    nodejson['children'] = []
    nodejson['CODE'] = rawnodejson['properties']['CODE']["@value"]
    nodejson['type'] = rawnodejson['label']
    nodejson['id'] = rawnodejson['id']
    for child in nodes[id].children:
        nodejson['children'].append(traversal(child,nodes,vertices))
    return nodejson

withName = ['METHOD','NAMESPACE','NAMESPACE_BLOCK','METHOD_PARAMETER_IN','METHOD_PARAMETER_OUT',
            'MEMBER','TYPE','TYPE_DECL','TYPE_PARAMETER','CALL','CALL_REPR',
            'IDENTIFIER','JUMP_LABEL','JUMP_TARGET','LOCAL','UNKNOWN']
withTypeFullName = ['METHOD_PARAMETER_IN','METHOD_PARAMETER_OUT','METHOD_RETURN','BLOCK'
                'LITERAL','METHOD_REF','TYPE_REF','UNKNOWN']
withModifierType = ['MODIFIER']

# 遍历并返回按顺序的AST结构,只保留关键部分用于生成ast diff
def traversal(id,nodes,vertices):
    rawnodejson = getV(id,vertices)
    nodejson = {}
    nodejson['type'] = rawnodejson['label']
    nodejson['code'] = rawnodejson['properties']['CODE']["@value"]
    #! 还是需要id的
    nodejson['id'] = rawnodejson['id']["@value"]
    # 函数/变量节点,value取其标识符;类型/声明,value取其名字
    if nodejson['type'] in withName:
        nodejson['value'] =  rawnodejson['properties']['NAME']["@value"]
    elif nodejson['type'] in withTypeFullName:
        nodejson['value'] =  rawnodejson['properties']['TYPE_FULL_NAME']["@value"]
    elif nodejson['type'] in withModifierType:
        nodejson['value'] =  rawnodejson['properties']['MODIFIER_TYPE']["@value"]
    nodejson['children'] = []
    for child in nodes[id].children:
        nodejson['children'].append(traversal(child,nodes,vertices))
    return nodejson


def getAST(jsonfile):
    cpgfile = open(jsonfile,'r')
    cpgjson = json.load(cpgfile)
    cpgfile.close()
    edges = cpgjson['@value']['edges']
    vertices = cpgjson['@value']['vertices']
    print(len(edges),len(vertices))
    nodes = {}
    for edge in edges:
        if(edge["label"] == "AST"):
            print(edge["outV"]['@value'],"->",edge["inV"]['@value'],edge["id"]['@value'],edge["label"])
            outid = str(edge["outV"]['@value'])
            inid = str(edge["inV"]['@value'])
            if not inid in nodes:
                nodes[inid] = astNode(inid)
            if not outid in nodes:
                nodes[outid] = astNode(outid)
            nodes[inid].setparent(outid)
            nodes[outid].addchild(inid)
    
    astjson = {}
    for node in nodes.values():
        if node.parent == "-1":
            print("root:",node.id)
            astjson["ast"] = traversal(node.id,nodes,vertices)
    jsondir = '/'.join(jsonfile.split('/')[:-1])
    astfile = os.path.join(jsondir,"ast.json")
    astfile = open(astfile,'w+')
    json.dump(astjson,astfile)
    astfile.close()

# 清理原始的cpg,移除无关的边,留下AST,CFG,DDG,CDG四类边 
def cpgClean(jsonfile):
    cpgfile = open(jsonfile,'r')
    cpgjson = json.load(cpgfile)
    cpgfile.close()
    for edge in cpgjson['@value']['edges']:
        if(edge["label"] == "AST" or edge["label"] == "CFG" or edge["label"] == "CDG"):
            continue
        elif edge["label"] == "REACHING_DEF":
            edge["label"] = "DDG"
        else:
            cpgjson['@value']['edges'].remove(edge)
    jsondir = '/'.join(jsonfile.split('/')[:-1])
    cpgfile = open(os.path.join(jsondir,"cpg.json"),'w+')
    json.dump(cpgjson,cpgfile)
    cpgfile.close()

# 从dot文件中获取按顺序排列的AST
def getASTfromDot(dotfile):
    dotsnode = open(dotfile,'r')
    nodes = {}
    for line in dotsnode.readlines():
        if "->" not in line:
            continue
        tmps = line.split(" ")
        for i in range(len(tmps)):
            if tmps[i] == "->":
                left,right = tmps[i-1][1:-1],tmps[i+1][1:-1]        
                if not left in nodes:
                    nodes[left] = astNode(left)
                if not right in nodes:
                    nodes[right] = astNode(right)
                nodes[right].setparent(left)
                nodes[left].addchild(right)
                break
    dotsnode.close()
    return nodes

# 基于dot-ast的骨架和清理后的cpg文件,构建新的层次式ast-json文件
def getJsonAST(jsonfile,nodes):
    cpgfile = open(jsonfile,'r')
    cpgjson = json.load(cpgfile)
    cpgfile.close()
    edges = cpgjson['@value']['edges']
    vertices = cpgjson['@value']['vertices']
    print(len(edges),len(vertices))
    
    astjson = {}
    for node in nodes.values():
        if node.parent == "-1":
            print("root:",node.id)
            astjson["ast"] = traversal(node.id,nodes,vertices)
    jsondir = '/'.join(jsonfile.split('/')[:-1])
    astfile = os.path.join(jsondir,"ast.json")
    astfile = open(astfile,'w+')
    json.dump(astjson,astfile)
    astfile.close()

# 有关Joern-export的步骤:
# joern-export支持export dot形式的各个图,已经json形式的cpg
# 同一份代码,解析出的不同的图的节点编号是一致的,但CPG中的AST是没有顺序的,所以要确定AST的结构,只能export出dot的ast,以此为骨架,添加上CPG的其他边
# 但dot中的ast信息不足,所以实际做法是从json的cpg中筛选出AST节点,并根据dot中的顺序进行排序
# 对于不同的程序,对比AST diff时应删去节点编号进行比对
if __name__ == '__main__':
    workdir = sys.argv[1]
    filename = sys.argv[2]
    prefix,suffix = os.path.splitext(filename)
    jsondir = os.path.join(workdir,'json',prefix+'.java')
    astfile = os.path.join(workdir,'outast','0-ast.dot')
    # 只处理单个函数的样本
    if len(os.listdir(jsondir)) > 2:
        print(filename)
    else:
        nodes = getASTfromDot(astfile)
        for file in os.listdir(jsondir):
            if file == "_init_.json":
                continue
            jsonfile = os.path.join(jsondir,file)
            cpgClean(jsonfile)
            getJsonAST(jsonfile,nodes)
        