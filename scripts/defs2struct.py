# レキシコンのjsonから構造体の定義するヘッダーを出力するツール
# https://github.com/bluesky-social/atproto/tree/main/lexicons
# query系のoutputからの参照を起点に定義を作った方が良いかもしれない

# python3 ./scripts/defs2struct.py ../atproto/lexicons/ ./app/atprotocol

import sys
import glob
import json


class Defs2Struct:
    def __init__(self) -> None:
        self.history = [] # <namespace>#<struct_name>
        self.history_namespace = []
        self.json_obj = {}  # [namespace] = obj
        self.output_text = {} # [namespace] = list(line)
        self.namespace_stack = []
        self.pre_define = {} # [namespace] = <struct_name>

        # QVariantに入れる構造体をQ_DECLARE_METATYPE()で定義する構造体
        # （単純にすべてではない）
        self.metatype = ('AppBskyFeedPost::Record', )

    def to_struct_style(self, name: str) -> str:
        return name[0].upper() + name[1:]

    def to_namespace_style(self, name: str) -> str:
        srcs = name.split('.')
        dest = []
        for src in srcs:
            dest.append(src[0].upper() + src[1:])
            # app.bsky.embed.recordWithMediaがあるのでcapitalize()は使えない
        return ''.join(dest)

    def split_ref(self, path: str) -> tuple:
        if '#' in path:
            return path.split('#')
        else:
            return (path, '')

    def get_defs_obj(self, namespace: str, type_name: str) -> dict:
        return self.json_obj.get(namespace, {}).get('defs', {}).get(type_name, {})

    def append_history(self, namespace: str, type_name: str):
        self.history.append(namespace + '#' + type_name)
        if namespace not in self.history_namespace:
            self.history_namespace.append(namespace)

    def append_pre_define(self, namespace: str, type_name: str):
        key = self.to_namespace_style(namespace)
        value = self.to_struct_style(type_name)
        if key in self.pre_define:
            if value not in self.pre_define[key]:
                self.pre_define[key].append(value)
        else:
            self.pre_define[key] = [value]

    def output_ref(self, namespace: str, property_name: str, ref_obj: dict, is_array: bool = False):
        (ref_namespace, ref_struct_name) = self.split_ref(ref_obj)
        if len(ref_struct_name) == 0:
            self.output_text[namespace].append('    // ref=%s' % (ref_namespace, ))
        else:
            extend_symbol = ''
            if len(ref_namespace) == 0:
                if (namespace + '#' + ref_struct_name) in self.namespace_stack:
                    extend_symbol = ' *'
                    self.append_pre_define(namespace, ref_struct_name)
                if not is_array:
                    if len(extend_symbol) == 0:
                        extend_symbol = ' '
                    self.output_text[namespace].append('    %s%s%s;' % (
                        self.to_struct_style(ref_struct_name), extend_symbol, property_name
                        ))
                else:
                    self.output_text[namespace].append('    QList<%s%s> %s;' % (
                        self.to_struct_style(ref_struct_name), extend_symbol, property_name
                        ))
            else:
                if (ref_namespace + '#' + ref_struct_name) in self.namespace_stack:
                    extend_symbol = ' *'
                    self.append_pre_define(ref_namespace, ref_struct_name)
                if not is_array:
                    if len(extend_symbol) == 0:
                        extend_symbol = ' '
                    self.output_text[namespace].append('    %s::%s%s%s;' % (
                        self.to_namespace_style(ref_namespace), self.to_struct_style(ref_struct_name), extend_symbol, property_name
                        ))
                else:
                    self.output_text[namespace].append('    QList<%s::%s%s> %s;' % (
                        self.to_namespace_style(ref_namespace), self.to_struct_style(ref_struct_name), extend_symbol, property_name
                        ))


    def output_union(self, namespace: str, type_name: str, property_name: str, refs_obj: dict, is_array: bool = False):
        union_name_list = []
        self.output_text[namespace].append('    // union start : %s' % (property_name, ))
        pos = len(self.output_text[namespace])
        for ref in refs_obj:
            (ref_namespace, ref_struct_name) = self.split_ref(ref)
            if len(ref_struct_name) == 0:
                self.output_text[namespace].append('    //     union=%s' % (ref_namespace, ))
            else:
                extend_symbol = ''
                if len(ref_namespace) == 0:
                    if (namespace + '#' + ref_struct_name) in self.namespace_stack:
                        extend_symbol = ' *'
                        self.append_pre_define(namespace, ref_struct_name)
                    union_name = '%s_%s' % (property_name, self.to_struct_style(ref_struct_name))
                    union_name_list.append(union_name)
                    if not is_array:
                        if len(extend_symbol) == 0:
                            extend_symbol = ' '
                        self.output_text[namespace].append('    %s%s%s;' % (
                            self.to_struct_style(ref_struct_name), extend_symbol, union_name
                            ))
                    else:
                        self.output_text[namespace].append('    QList<%s%s> %s;' % (
                            self.to_struct_style(ref_struct_name), extend_symbol, union_name
                            ))
                else:
                    if (ref_namespace + '#' + ref_struct_name) in self.namespace_stack:
                        extend_symbol = ' *'
                        self.append_pre_define(ref_namespace, ref_struct_name)
                    union_name = '%s_%s_%s' % (property_name, self.to_namespace_style(ref_namespace), self.to_struct_style(ref_struct_name))
                    union_name_list.append(union_name)
                    if not is_array:
                        if len(extend_symbol) == 0:
                            extend_symbol = ' '
                        self.output_text[namespace].append('    %s::%s%s%s;' % (
                            self.to_namespace_style(ref_namespace), self.to_struct_style(ref_struct_name), extend_symbol, union_name
                            ))
                    else:
                        self.output_text[namespace].append('    QList<%s::%s%s> %s;' % (
                            self.to_namespace_style(ref_namespace), self.to_struct_style(ref_struct_name), extend_symbol, union_name
                            ))
        self.output_text[namespace].append('    // union end : %s' % (property_name, ))

        # enumの定義挿入
        if len(union_name_list) > 0:
            union_type_name = '%s%sType' % (self.to_struct_style(type_name), self.to_struct_style(property_name), )
            self.output_text[namespace].insert(pos, '    %s %s_type = %s::none;' % (union_type_name, property_name, union_type_name, ))
            ins_pos = 0
            self.output_text[namespace].insert(ins_pos, 'enum class %s : int {' % (union_type_name, ))
            ins_pos += 1
            self.output_text[namespace].insert(ins_pos, '    none,')
            ins_pos += 1
            for union_name in union_name_list:
                self.output_text[namespace].insert(ins_pos, '    %s,' % (union_name, ))
                ins_pos += 1
            self.output_text[namespace].insert(ins_pos, '};')

    def output_ref_recursive(self, namespace: str, type_name: str, ref: str):
        (ref_namespace, ref_struct_name) = self.split_ref(ref)
        if len(ref_struct_name) == 0:
            pass
        elif len(ref_namespace) == 0:
            # if ref_struct_name == type_name:
            if (namespace + '#' + ref_struct_name) in self.namespace_stack:
                # infinite loop
                pass
            else:
                self.output_type(namespace, ref_struct_name, self.get_defs_obj(namespace, ref_struct_name))
        else:
            if (ref_namespace + '#' + ref_struct_name) in self.namespace_stack:
            # if ref_namespace == namespace and ref_struct_name == type_name:
                # infinite loop
                pass
            else:
                if ref_namespace != namespace and ref_namespace not in self.history_namespace:
                    # 名前空間が違う場合は自分の名前空間より前に履歴を差し込む
                    # 同一名前空間で参照のない構造体を先に処理すると順番が後になってしまうため
                    for i, value in enumerate(self.history_namespace):
                        if value == namespace:
                            self.history_namespace.insert(i, ref_namespace)
                            break
                self.output_type(ref_namespace, ref_struct_name, self.get_defs_obj(ref_namespace, ref_struct_name))

    def output_type(self, namespace: str, type_name: str, obj: dict):
        if (namespace + '#' + type_name) in self.history:
            # already outputted
            return

        self.namespace_stack.append(namespace + '#' + type_name)

        if namespace not in self.output_text:
            self.output_text[namespace] = []

        if obj.get('type') == 'object':
            # 構造体
            properties = obj.get('properties', {})
            # refかunionのときはその型を先に処理する
            for property_name in properties.keys():
                p_type = properties[property_name].get('type')
                if p_type == 'ref':
                    self.output_ref_recursive(namespace, type_name, properties[property_name].get('ref', ''))

                elif p_type == 'union':
                    for ref in properties[property_name].get('refs', []):
                        self.output_ref_recursive(namespace, type_name, ref)

                elif p_type == 'array':
                    items_type = properties[property_name].get('items', {}).get('type', '')
                    if items_type == 'ref':
                        self.output_ref_recursive(namespace, type_name, properties[property_name].get('items', {}).get('ref', ''))
                    elif items_type == 'union':
                        for ref in properties[property_name].get('items', {}).get('refs', []):
                            self.output_ref_recursive(namespace, type_name, ref)

            # 実際に出力する
            self.output_text[namespace].append('struct %s' % (self.to_struct_style(type_name), ))
            self.output_text[namespace].append('{')
            for property_name in properties.keys():
                p_type = properties[property_name].get('type')
                if p_type == 'ref':
                    self.output_ref(namespace, property_name, properties[property_name].get('ref', {}))
                elif p_type == 'union':
                    self.output_union(namespace, type_name, property_name, properties[property_name].get('refs', []))
                elif p_type == 'unknown':
                    self.output_text[namespace].append('    QVariant %s;' % (property_name, ))
                elif p_type == 'integer':
                    self.output_text[namespace].append('    int %s = 0;' % (property_name, ))
                elif p_type == 'string':
                    comment = properties[property_name].get('format', '')
                    if len(comment) > 0:
                        self.output_text[namespace].append('    QString %s; // %s' % (property_name, comment))
                    else:
                        self.output_text[namespace].append('    QString %s; //' % (property_name, ))
                elif p_type == 'array':
                    items_type = properties[property_name].get('items', {}).get('type', '')
                    if items_type == 'ref':
                        self.output_ref(namespace, property_name, properties[property_name].get('items', {}).get('ref', {}), True)
                    elif items_type == 'union':
                        self.output_union(namespace, type_name, property_name, properties[property_name].get('items', {}).get('refs', []), True)

            self.output_text[namespace].append('};')

            self.append_history(namespace, type_name)

        elif obj.get('type') == 'string':
            # 文字列は型定義にする
            self.output_text[namespace].append('typedef QString %s;' % (self.to_struct_style(type_name), ))
            self.append_history(namespace, type_name)

        elif obj.get('type') == 'integer':
            # 数値は型定義にする
            self.output_text[namespace].append('typedef int %s;' % (self.to_struct_style(type_name), ))
            self.append_history(namespace, type_name)

        else:
            variant_key = obj.get('type', '')
            variant_obj = obj.get(variant_key)
            if variant_obj is not None:
                self.output_type(namespace, variant_key, variant_obj)

            # assert obj.get('type') == 'object', 'A type that is not a candidate for structure.'

        self.namespace_stack.pop()

    def output(self, output_path: str):
        # 各ファイル（名前空間）ごとに解析する
        for namespace in self.json_obj.keys():
            if namespace not in self.output_text:
                self.output_text[namespace] = []

            description = self.json_obj[namespace].get('description', '')
            if len(description) > 0:
                self.output_text[namespace].append('// %s' % (description, ))

            defs = self.json_obj[namespace].get('defs', {})
            for type_name in defs.keys():
                self.output_type(namespace, type_name, self.get_defs_obj(namespace, type_name))

        with open(output_path + '/lexicons.h', 'w', encoding='utf-8') as fp:
            # for debug
            # print('class QString{};')
            # print('template <typename T>')
            # print('class QList{};')

            fp.write('// This file is generated by "defs2struct.py".\n')
            fp.write('// Please do not edit.\n')
            fp.write('\n')
            fp.write('#ifndef LEXICONS_H\n')
            fp.write('#define LEXICONS_H\n')
            fp.write('\n')
            fp.write('#include <QList>\n')
            fp.write('#include <QString>\n')
            fp.write('#include <QVariant>\n')
            fp.write('\n')
            for namespace in sorted(self.pre_define.keys()):
                fp.write('namespace %s {\n' % (namespace, ))
                for type_name in sorted(self.pre_define[namespace]):
                    fp.write('struct %s;\n' % (type_name, ))
                fp.write('}\n')
            fp.write('\n')

            for namespace in self.history_namespace:
                fp.write('namespace %s {\n' % (self.to_namespace_style(namespace), ))
                fp.write('\n'.join(self.output_text[namespace]))
                fp.write('\n')
                fp.write('}\n')
                fp.write('\n')

            for name in self.metatype:
                fp.write('Q_DECLARE_METATYPE(%s)\n' % (name, ))

            fp.write('\n')
            fp.write('#endif // LEXICONS_H\n')

            fp.close()

    def open(self, path: str, base_path: str):
        obj = None
        with open(path, 'r') as fp:
            obj = json.load(fp)
        if obj is None:
            print('Failed to load json file')
            return
        rel_path = path.removeprefix(base_path).removesuffix('.json')
        if rel_path[0] == '/':
            rel_path = rel_path[1:]
        namespace = rel_path.replace('/', '.')

        self.json_obj[namespace] = obj

def main(path: str, output_path: str):

    def2struct = Defs2Struct()
    #atproto\lexicons
    path = path.replace('\\', '/')
    file_list = glob.glob(path + '/**/*.json', recursive=True)
    for file in file_list:
        def2struct.open(file.replace('\\', '/'), path)

    def2struct.output(output_path)

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print('usage: python defs2struct.py path/to/atproto/lexicons path/to/lexicons.h')
        print('   atproto/lexicons : https://github.com/bluesky-social/atproto/tree/main/lexicons')
        exit(1)

    path = sys.argv[1]
    output = sys.argv[2]

    main(path, output)
