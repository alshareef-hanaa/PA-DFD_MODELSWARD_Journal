import sys
import xml.etree.ElementTree as ET
import csv


# function for producing dfd in csv format
def initialize(xmlfile_DFD, csvfile_DFD):
    tree = ET.parse(xmlfile_DFD)
    root = tree.getroot()
    newsitems = []

    for subroot in root:
        for subsubroot in subroot:
            for subsubsubroot in subsubroot:
                for child in subsubsubroot:
                    news = {}
                    if int(child.attrib['id']) >= 2:
                        news['id'] = child.attrib['id']
                        news['value'] = child.attrib['value']
                        if child.attrib['style'].startswith("rounded=0"):
                            news['style'] = 'rounded=0'
                            news['source'] = 'null'
                            news['target'] = 'null'
                            news['type'] = 'external_entity'
                        elif "doubleEllipse" in child.attrib['style']:
                            news['style'] = 'ellipse;shape=doubleEllipse'
                            news['source'] = 'null'
                            news['target'] = 'null'
                            news['type'] = 'composite_process'
                        elif child.attrib['style'].startswith("ellipse"):
                            news['style'] = 'ellipse'
                            news['source'] = 'null'
                            news['target'] = 'null'
                            news['type'] = 'process'
                        elif child.attrib['style'].startswith("shape"):
                            news['style'] = 'shape=partialRectangle'
                            news['source'] = 'null'
                            news['target'] = 'null'
                            news['type'] = 'data_base'
                        elif child.attrib['style'].startswith("endArrow=classic"):
                            news['source'] = child.attrib['source']
                            news['target'] = child.attrib['target']
                            news['style'] = 'endArrow=classic'
                            news['type'] = 'endArrow=classic'
                        elif child.attrib['style'].startswith("endArrow=cross"):
                            news['source'] = child.attrib['source']
                            news['target'] = child.attrib['target']
                            news['style'] = 'endArrow=cross'
                            news['type'] = 'endArrow=cross'
                        newsitems.append(news)

    fields = ['id', 'value', 'style', 'source', 'target', 'type']
    with open(csvfile_DFD, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(newsitems)


# this function changes the format of DFD from csv to dic
def generate_list_dfd(filename):
    data = csv.DictReader(open(filename))
    data_dic = []
    for row in data:
        data_dic.append(row)
    return data_dic


# this function changes the format of DFD from dic to nested dic
# where key is the id of each DFD element (activators and flows)
def generate_dfd_graph(original):
    output = {}
    for elem in original:
        output[elem['id']] = elem
    return output


# this function assigns type to each flow in DFD (that format as nested dic)
def get_data_flow_types(dfd_graph):
    for index, data_flow in dfd_graph.items():
        if data_flow['style'] == 'endArrow=classic':
            if dfd_graph[data_flow['source']]['style'] == 'rounded=0' and dfd_graph[data_flow['target']][
                'style'] == 'ellipse':
                dfd_graph[index]['type'] = 'in'
            if dfd_graph[data_flow['source']]['style'] == 'rounded=0' and dfd_graph[data_flow['target']][
                'style'] == 'ellipse;shape=doubleEllipse':
                dfd_graph[index]['type'] = 'inc'
            elif dfd_graph[data_flow['source']]['style'] == 'ellipse' and dfd_graph[data_flow['target']][
                'style'] == 'rounded=0':
                dfd_graph[index]['type'] = 'out'
            elif dfd_graph[data_flow['source']]['style'] == 'ellipse;shape=doubleEllipse' and \
                    dfd_graph[data_flow['target']]['style'] == 'rounded=0':
                dfd_graph[index]['type'] = 'cout'
            elif (dfd_graph[data_flow['source']]['style'] == 'ellipse' and dfd_graph[data_flow['target']][
                'style'] == 'ellipse'):
                dfd_graph[index]['type'] = 'comp'
            elif (dfd_graph[data_flow['source']]['style'] == 'ellipse;shape=doubleEllipse' and
                  dfd_graph[data_flow['target']]['style'] == 'ellipse;shape=doubleEllipse'):
                dfd_graph[index]['type'] = 'ccompc'
            elif (dfd_graph[data_flow['source']]['style'] == 'ellipse;shape=doubleEllipse' and
                  dfd_graph[data_flow['target']]['style'] == 'ellipse'):
                dfd_graph[index]['type'] = 'ccomp'
            elif (dfd_graph[data_flow['source']]['style'] == 'ellipse' and
                  dfd_graph[data_flow['target']]['style'] == 'ellipse;shape=doubleEllipse'):
                dfd_graph[index]['type'] = 'compc'
            elif dfd_graph[data_flow['source']]['style'] == 'ellipse' and dfd_graph[data_flow['target']][
                'style'] == 'shape=partialRectangle':
                dfd_graph[index]['type'] = 'store'
            elif dfd_graph[data_flow['source']]['style'] == 'ellipse;shape=doubleEllipse' and \
                    dfd_graph[data_flow['target']][
                        'style'] == 'shape=partialRectangle':
                dfd_graph[index]['type'] = 'cstore'
            elif dfd_graph[data_flow['source']]['style'] == 'shape=partialRectangle' and dfd_graph[data_flow['target']][
                'style'] == 'ellipse':
                dfd_graph[index]['type'] = 'read'
            elif dfd_graph[data_flow['source']]['style'] == 'shape=partialRectangle' and dfd_graph[data_flow['target']][
                'style'] == 'ellipse;shape=doubleEllipse':
                dfd_graph[index]['type'] = 'readc'
            if data_flow['style'] == 'endArrow=cross':
                if dfd_graph[data_flow['source']]['style'] == 'ellipse' and dfd_graph[data_flow['target']][
                    'style'] == 'shape=partialRectangle':
                    dfd_graph[index]['type'] = 'delete'
                elif dfd_graph[data_flow['source']]['style'] == 'ellipse;shape=doubleEllipse' and \
                        dfd_graph[data_flow['target']]['style'] == 'shape=partialRectangle':
                    dfd_graph[index]['type'] = 'cdelete'
    return dfd_graph


# this function add the common entities in transformation process
def add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements, limit_counter, request_counter, log_counter,
                               DB_log_counter):
    # add the new elements
    dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'limit %d' % limit_counter,
                                            'style': 'ellipse', 'source': 'null', 'target': 'null',
                                            'type': 'limit'}
    len_of_dfd_elements = len_of_dfd_elements + 1
    dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': ''
                                                                                'request %d' % request_counter,
                                            'style': 'ellipse', 'source': 'null', 'target': 'null',
                                            'type': 'request'}
    len_of_dfd_elements = len_of_dfd_elements + 1
    dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'log %d' % log_counter,
                                            'style': 'ellipse', 'source': 'null', 'target': 'null',
                                            'type': 'log'}
    len_of_dfd_elements = len_of_dfd_elements + 1
    dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'DB log %d' % DB_log_counter,
                                            'style': 'shape=partialRectangle', 'source': 'null',
                                            'target': 'null', 'type': 'DB_log'}
    len_of_dfd_elements = len_of_dfd_elements + 1

    return dfd_graph_typed, len_of_dfd_elements


# this function applies PA-DFD transformation algorithm and produces PA-DFD nested dic
def generate_pa_dfd_graph(dfd_graph_typed):
    len_of_dfd_elements = len(dfd_graph_typed) + 2

    # for transformation, we add new reason process for each process type
    reason_counter = 0
    for index, data_flow_typed in list(dfd_graph_typed.items()):
        if data_flow_typed['style'] == 'ellipse' and data_flow_typed['type'] == 'process':
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'reason %s' % data_flow_typed['value'],
                                                    'style': 'ellipse', 'source': 'null',
                                                    'target': 'null', 'type': 'reason',
                                                    'for_process': data_flow_typed['id']}
            len_of_dfd_elements = len_of_dfd_elements + 1
            reason_counter = reason_counter + 1

    # for transformation, we add new policy data base for each type
    pol_DB_counter = 0
    for index, data_flow_typed in list(dfd_graph_typed.items()):
        if data_flow_typed['style'] == 'shape=partialRectangle' and data_flow_typed['type'] == 'data_base':
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'policy %d' % pol_DB_counter,
                                                    'style': 'shape=partialRectangle', 'source': 'null',
                                                    'target': 'null', 'type': 'pol_DB',
                                                    'for_DB': data_flow_typed['id']}
            len_of_dfd_elements = len_of_dfd_elements + 1
            pol_DB_counter = pol_DB_counter + 1

    # to transform each type of data flows
    limit_counter = 0
    request_counter = 0
    log_counter = 0
    DB_log_counter = 0
    DB_pol_counter = 0
    clean_counter = 0

    # transfer all types of flow except comp
    for index, data_flow_typed in list(dfd_graph_typed.items()):

        # transform the 'in' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'in':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_in_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_in_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': data_flow_typed['value'],
                                                    'style': 'endArrow=classic', 'source': data_flow_typed['source'],
                                                    'target': target_in_limit, 'type': 'extlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            target_in_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_in_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic', 'source': data_flow_typed['source'],
                                                    'target': target_in_request, 'type': 'extreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_log = None
            target_in_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_in_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_in_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_in_log,
                                                    'target': target_in_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_DB_log = None
            target_in_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_in_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_in_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_in_DB_log,
                                                    'target': target_in_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_pol_limit = None
            target_in_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_in_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_in_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic', 'source': source_in_pol_limit,
                                                    'target': target_in_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_pol_out_request = None
            target_in_pol_out_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_in_pol_out_request = value['id']
                    first_condition = True
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['target']):
                    target_in_pol_out_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic', 'source': source_in_pol_out_request,
                                                    'target': target_in_pol_out_request, 'type': 'reqrea'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_limit_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_in_limit_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?', 'style': 'endArrow=classic',
                                      'source': source_in_limit_process,
                                      'target': data_flow_typed['target'], 'type': 'limpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'inc' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'inc':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_in_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_in_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': data_flow_typed['value'],
                                                    'style': 'endArrow=classic', 'source': data_flow_typed['source'],
                                                    'target': target_in_limit, 'type': 'extlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            target_in_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_in_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic', 'source': data_flow_typed['source'],
                                                    'target': target_in_request, 'type': 'extreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_log = None
            target_in_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_in_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_in_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_in_log,
                                                    'target': target_in_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_DB_log = None
            target_in_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_in_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_in_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_in_DB_log,
                                                    'target': target_in_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_pol_limit = None
            target_in_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_in_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_in_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic', 'source': source_in_pol_limit,
                                                    'target': target_in_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_limit_comp_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_in_limit_comp_process = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_in_limit_comp_process,
                                                    'target': data_flow_typed['target'], 'type': 'reqcpro'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_in_limit_comp_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_in_limit_comp_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?', 'style': 'endArrow=classic',
                                      'source': source_in_limit_comp_process,
                                      'target': data_flow_typed['target'], 'type': 'limcpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'out' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'out':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_out_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_out_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_out_limit, 'type': 'porlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_request = None
            target_out_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['source']):
                    source_out_request = value['id']
                    first_condition = True
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_out_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_out_request,
                                                    'target': target_out_request, 'type': 'reareq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_log = None
            target_out_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_out_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_out_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_out_log,
                                                    'target': target_out_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_DB_log = None
            target_out_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_out_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_out_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_out_DB_log,
                                                    'target': target_out_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_pol_limit = None
            target_out_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_out_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_out_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_out_pol_limit,
                                                    'target': target_out_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_pol_out_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_out_pol_out_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_out_pol_out_request,
                                                    'target': data_flow_typed['target'], 'type': 'reqext'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_limit_external_entity = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_out_limit_external_entity = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?', 'style': 'endArrow=classic',
                                      'source': source_out_limit_external_entity,
                                      'target': data_flow_typed['target'], 'type': 'limext'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'cout' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'cout':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_out_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_out_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_out_limit, 'type': 'cprolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            target_out_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_out_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_out_request, 'type': 'cproreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_log = None
            target_out_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_out_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_out_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_out_log,
                                                    'target': target_out_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_DB_log = None
            target_out_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_out_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_out_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_out_DB_log,
                                                    'target': target_out_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_pol_limit = None
            target_out_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_out_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_out_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_out_pol_limit,
                                                    'target': target_out_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_pol_out_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_out_pol_out_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_out_pol_out_request,
                                                    'target': data_flow_typed['target'], 'type': 'reqext'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_out_limit_external_entity = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_out_limit_external_entity = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?',
                                      'style': 'endArrow=classic',
                                      'source': source_out_limit_external_entity,
                                      'target': data_flow_typed['target'], 'type': 'limext'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'store' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'store':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new elements
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'clean %d' % clean_counter,
                                                    'style': 'ellipse', 'source': 'null', 'target': 'null',
                                                    'type': 'clean'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # add the new data flow
            target_store_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_store_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_store_limit, 'type': 'porlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_request = None
            target_store_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['source']):
                    source_store_request = value['id']
                    first_condition = True
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_store_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_store_request,
                                                    'target': target_store_request, 'type': 'resreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_pol_out_request = None
            target_store_pol_out_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_store_pol_out_request = value['id']
                    first_condition = True
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['target']):
                    target_store_pol_out_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_store_pol_out_request,
                                                    'target': target_store_pol_out_request,
                                                    'type': 'reqpdb'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # changed this to request -> limit
            source_store_pol_limit = None
            target_store_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_store_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_store_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_store_pol_limit,
                                                    'target': target_store_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_log = None
            target_store_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_store_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_store_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_store_log,
                                                    'target': target_store_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_DB_log = None
            target_store_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_store_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_store_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_store_DB_log,
                                                    'target': target_store_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_pol_clean = None
            target_store_pol_clean = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['target']):
                    source_store_pol_clean = value['id']
                    first_condition = True
                if value['type'] == 'clean' and value['value'].endswith(str(clean_counter)):
                    target_store_pol_clean = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_store_pol_clean,
                                                    'target': target_store_pol_clean, 'type': 'pdbcle'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_ref_clean = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'clean' and value['value'].endswith(str(clean_counter)):
                    source_store_ref_clean = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref', 'style': 'endArrow=cross',
                                                    'source': source_store_ref_clean,
                                                    'target': data_flow_typed['target'], 'type': 'cledb_del'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_limit_data_base = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_store_limit_data_base = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?', 'style': 'endArrow=classic',
                                      'source': source_store_limit_data_base,
                                      'target': data_flow_typed['target'], 'type': 'limdb'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            DB_pol_counter = DB_pol_counter + 1
            clean_counter = clean_counter + 1

        # transform the 'cstore' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'cstore':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new elements
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'clean %d' % clean_counter,
                                                    'style': 'ellipse', 'source': 'null', 'target': 'null',
                                                    'type': 'clean'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # add the new data flow
            target_store_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_store_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_store_limit, 'type': 'cprolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            target_store_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_store_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_store_request, 'type': 'cproreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_pol_out_request = None
            target_store_pol_out_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_store_pol_out_request = value['id']
                    first_condition = True
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['target']):
                    target_store_pol_out_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_store_pol_out_request,
                                                    'target': target_store_pol_out_request,
                                                    'type': 'reqpdb'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # changed this to request -> limit
            source_store_pol_limit = None
            target_store_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_store_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_store_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_store_pol_limit,
                                                    'target': target_store_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_log = None
            target_store_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_store_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_store_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_store_log,
                                                    'target': target_store_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_DB_log = None
            target_store_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_store_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_store_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_store_DB_log,
                                                    'target': target_store_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_pol_clean = None
            target_store_pol_clean = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['target']):
                    source_store_pol_clean = value['id']
                    first_condition = True
                if value['type'] == 'clean' and value['value'].endswith(str(clean_counter)):
                    target_store_pol_clean = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_store_pol_clean,
                                                    'target': target_store_pol_clean, 'type': 'pdbcle'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_ref_clean = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'clean' and value['value'].endswith(str(clean_counter)):
                    source_store_ref_clean = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref', 'style': 'endArrow=cross',
                                                    'source': source_store_ref_clean,
                                                    'target': data_flow_typed['target'], 'type': 'cledb_del'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_store_limit_data_base = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_store_limit_data_base = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?',
                                      'style': 'endArrow=classic',
                                      'source': source_store_limit_data_base,
                                      'target': data_flow_typed['target'], 'type': 'limdb'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            DB_pol_counter = DB_pol_counter + 1
            clean_counter = clean_counter + 1

        # transform the 'read' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'read':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_read_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_read_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'],
                                                    'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_read_limit, 'type': 'dblim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_request = None
            target_read_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['source']):
                    source_read_request = value['id']
                    first_condition = True
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_read_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_read_request,
                                                    'target': target_read_request, 'type': 'pdbreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_pol_limit = None
            target_read_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_read_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_read_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_read_pol_limit,
                                                    'target': target_read_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_log = None
            target_read_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_read_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_read_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_read_log,
                                                    'target': target_read_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_DB_log = None
            target_read_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_read_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_read_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_read_DB_log,
                                                    'target': target_read_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # *** something wrong here ***
            source_read_pol_out_request = None
            target_read_pol_out_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_read_pol_out_request = value['id']
                    first_condition = True
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['target']):
                    target_read_pol_out_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_read_pol_out_request,
                                                    'target': target_read_pol_out_request,
                                                    'type': 'reqrea'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_limit_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_read_limit_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?', 'style': 'endArrow=classic',
                                      'source': source_read_limit_process,
                                      'target': data_flow_typed['target'], 'type': 'limpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'readc' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'readc':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_read_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_read_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'],
                                                    'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_read_limit, 'type': 'dblim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_request = None
            target_read_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['source']):
                    source_read_request = value['id']
                    first_condition = True
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_read_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_read_request,
                                                    'target': target_read_request, 'type': 'pdbreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_pol_limit = None
            target_read_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_read_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_read_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_read_pol_limit,
                                                    'target': target_read_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_log = None
            target_read_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_read_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_read_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_read_log,
                                                    'target': target_read_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_DB_log = None
            target_read_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_read_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_read_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_read_DB_log,
                                                    'target': target_read_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_pol_out_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_read_pol_out_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_read_pol_out_request,
                                                    'target': data_flow_typed['target'], 'type': 'reqcpro'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_read_limit_composite_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_read_limit_composite_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': data_flow_typed['value'] + '?',
                                      'style': 'endArrow=classic',
                                      'source': source_read_limit_composite_process,
                                      'target': data_flow_typed['target'], 'type': 'limcpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'delete' type of data flow
        if data_flow_typed['style'] == 'endArrow=cross' and data_flow_typed['type'] == 'delete':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_del_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_del_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref (%s)' % data_flow_typed['value'],
                                                    'style': 'endArrow=classic', 'source': data_flow_typed['source'],
                                                    'target': target_del_limit, 'type': 'prolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_request = None
            target_del_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['source']):
                    source_del_request = value['id']
                    first_condition = True
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_del_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_del_request,
                                                    'target': target_del_request, 'type': 'reareq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_pol_limit = None
            target_del_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_del_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_del_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_del_pol_limit,
                                                    'target': target_del_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_log = None
            target_del_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_del_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_del_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref  (%s)' % data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_del_log,
                                                    'target': target_del_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_DB_log = None
            target_del_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_del_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_del_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref  (%s)' % data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_del_DB_log,
                                                    'target': target_del_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_pol_out_request = None
            target_del_pol_out_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_del_pol_out_request = value['id']
                    first_condition = True
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['target']):
                    target_del_pol_out_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_del_pol_out_request,
                                                    'target': target_del_pol_out_request,
                                                    'type': 'reqpdb'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_data_base = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_del_data_base = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': 'ref  (%s) ?' % data_flow_typed['value'],
                                      'style': 'endArrow=cross', 'source': source_del_data_base,
                                      'target': data_flow_typed['target'], 'type': 'limdb_del'}
            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'cdelete' type of data flow
        if data_flow_typed['style'] == 'endArrow=cross' and data_flow_typed['type'] == 'cdelete':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_del_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_del_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref (%s)' % data_flow_typed['value'],
                                                    'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_del_limit, 'type': 'cprolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            target_del_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_del_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol',
                                                    'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_del_request, 'type': 'cproreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_pol_limit = None
            target_del_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_del_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_del_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_del_pol_limit,
                                                    'target': target_del_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_log = None
            target_del_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_del_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_del_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref  (%s)' % data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_del_log,
                                                    'target': target_del_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_DB_log = None
            target_del_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_del_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_del_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'ref  (%s)' % data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic', 'source': source_del_DB_log,
                                                    'target': target_del_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_pol_out_request = None
            target_del_pol_out_request = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_del_pol_out_request = value['id']
                    first_condition = True
                if value['type'] == 'pol_DB' and value['for_DB'] == str(data_flow_typed['target']):
                    target_del_pol_out_request = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_del_pol_out_request,
                                                    'target': target_del_pol_out_request,
                                                    'type': 'reqpdb'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_del_data_base = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_del_data_base = value['id']
                    break
            dfd_graph_typed[index] = {'id': index, 'value': 'ref  (%s) ?' % data_flow_typed['value'],
                                      'style': 'endArrow=cross', 'source': source_del_data_base,
                                      'target': data_flow_typed['target'], 'type': 'limdb_del'}
            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            # DB_pol_counter = DB_pol_counter+1
            # clean_counter = clean_counter+1

        # transform the 'comp' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'comp':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_comp_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_comp_limit, 'type': 'prolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # value of the pol should be the updated one which is related to updated data
            source_comp_reason = None
            target_comp_reason = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['source']):
                    source_comp_reason = value['id']
                    first_condition = True
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_comp_reason = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_comp_reason,
                                                    'target': target_comp_reason, 'type': 'reareq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_log = None
            target_comp_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_comp_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_log,
                                                    'target': target_comp_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_DB_log = None
            target_comp_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_comp_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_comp_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_DB_log,
                                                    'target': target_comp_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # updated pol here that generated from reason of the sources process of this comp flow type
            source_comp_pol_limit = None
            target_comp_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_comp_pol_limit,
                                                    'target': target_comp_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # updated pol here that generated from reason of the sources process of this comp flow type
            source_comp_request_reason = None
            target_comp_request_reason = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_request_reason = value['id']
                    first_condition = True
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['target']):
                    target_comp_request_reason = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_request_reason,
                                                    'target': target_comp_request_reason,
                                                    'type': 'reqrea'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_limit_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_limit_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index,
                                      'value': data_flow_typed['value'] + '?',
                                      'style': 'endArrow=classic',
                                      'source': source_comp_limit_process,
                                      'target': data_flow_typed['target'],
                                      'type': 'limpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            DB_pol_counter = DB_pol_counter + 1
            clean_counter = clean_counter + 1

        # transform the 'ccomp' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'ccomp':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_comp_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_comp_limit, 'type': 'cprolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            target_comp_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_comp_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_comp_request, 'type': 'cproreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_log = None
            target_comp_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_comp_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_log,
                                                    'target': target_comp_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_DB_log = None
            target_comp_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_comp_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_comp_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_DB_log,
                                                    'target': target_comp_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # updated pol here that generated from reason of the sources process of this comp flow type
            source_comp_pol_limit = None
            target_comp_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_comp_pol_limit,
                                                    'target': target_comp_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # updated pol here that generated from reason of the sources process of this comp flow type
            source_comp_request_reason = None
            target_comp_request_reason = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_request_reason = value['id']
                    first_condition = True
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['target']):
                    target_comp_request_reason = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_request_reason,
                                                    'target': target_comp_request_reason,
                                                    'type': 'reqrea'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_limit_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_limit_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index,
                                      'value': data_flow_typed['value'] + '?',
                                      'style': 'endArrow=classic',
                                      'source': source_comp_limit_process,
                                      'target': data_flow_typed['target'],
                                      'type': 'limpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            DB_pol_counter = DB_pol_counter + 1
            clean_counter = clean_counter + 1

        # transform the 'compc' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'compc':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_comp_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_comp_limit, 'type': 'prolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # value of the pol should be the updated one which is related to updated data
            source_comp_reason = None
            target_comp_reason = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'reason' and value['for_process'] == str(data_flow_typed['source']):
                    source_comp_reason = value['id']
                    first_condition = True
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_comp_reason = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_comp_reason,
                                                    'target': target_comp_reason, 'type': 'reareq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_log = None
            target_comp_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_comp_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_log,
                                                    'target': target_comp_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_DB_log = None
            target_comp_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_comp_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_comp_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_DB_log,
                                                    'target': target_comp_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # updated pol here that generated from reason of the sources process of this comp flow type
            source_comp_pol_limit = None
            target_comp_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_comp_pol_limit,
                                                    'target': target_comp_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_request_composite_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_request_composite_process = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_request_composite_process,
                                                    'target': data_flow_typed['target'],
                                                    'type': 'reqcpro'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_limit_composite_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_limit_composite_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index,
                                      'value': data_flow_typed['value'] + '?',
                                      'style': 'endArrow=classic',
                                      'source': source_comp_limit_composite_process,
                                      'target': data_flow_typed['target'],
                                      'type': 'limcpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            DB_pol_counter = DB_pol_counter + 1
            clean_counter = clean_counter + 1

        # transform the 'ccompc' type of data flow
        if data_flow_typed['style'] == 'endArrow=classic' and data_flow_typed['type'] == 'ccompc':
            # add the new elements (common entities)
            dfd_graph_typed, len_of_dfd_elements = add_common_entities_pa_dfd(dfd_graph_typed, len_of_dfd_elements,
                                                                              limit_counter, request_counter,
                                                                              log_counter, DB_log_counter)
            # add the new data flow
            target_comp_limit = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_limit = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'], 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_comp_limit, 'type': 'cprolim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            target_comp_request = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    target_comp_request = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': data_flow_typed['source'],
                                                    'target': target_comp_request, 'type': 'cproreq'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_log = None
            target_comp_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_log = value['id']
                    first_condition = True
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    target_comp_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_log,
                                                    'target': target_comp_log, 'type': 'limlog'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_DB_log = None
            target_comp_DB_log = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'log' and value['value'].endswith(str(log_counter)):
                    source_comp_DB_log = value['id']
                    first_condition = True
                if value['type'] == 'DB_log' and value['value'].endswith(str(DB_log_counter)):
                    target_comp_DB_log = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': data_flow_typed['value'] + ',pol' + ',v',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_DB_log,
                                                    'target': target_comp_DB_log, 'type': 'logging'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            # updated pol here that generated from reason of the sources process of this comp flow type
            source_comp_pol_limit = None
            target_comp_pol_limit = None
            first_condition = False
            second_condition = False
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_pol_limit = value['id']
                    first_condition = True
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    target_comp_pol_limit = value['id']
                    second_condition = True
                if first_condition and second_condition:
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements,
                                                    'value': 'pol', 'style': 'endArrow=classic',
                                                    'source': source_comp_pol_limit,
                                                    'target': target_comp_pol_limit, 'type': 'reqlim'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_request_composite_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'request' and value['value'].endswith(str(request_counter)):
                    source_comp_request_composite_process = value['id']
                    break
            dfd_graph_typed[len_of_dfd_elements] = {'id': len_of_dfd_elements, 'value': 'pol',
                                                    'style': 'endArrow=classic',
                                                    'source': source_comp_request_composite_process,
                                                    'target': data_flow_typed['target'],
                                                    'type': 'reqcpro'}
            len_of_dfd_elements = len_of_dfd_elements + 1

            source_comp_limit_composite_process = None
            for key, value in dfd_graph_typed.items():
                if value['type'] == 'limit' and value['value'].endswith(str(limit_counter)):
                    source_comp_limit_composite_process = value['id']
                    break
            dfd_graph_typed[index] = {'id': index,
                                      'value': data_flow_typed['value'] + '?',
                                      'style': 'endArrow=classic',
                                      'source': source_comp_limit_composite_process,
                                      'target': data_flow_typed['target'],
                                      'type': 'limcpro'}

            limit_counter = limit_counter + 1
            request_counter = request_counter + 1
            log_counter = log_counter + 1
            DB_log_counter = DB_log_counter + 1
            DB_pol_counter = DB_pol_counter + 1
            clean_counter = clean_counter + 1

    return dfd_graph_typed


def generate_pa_dfd_csv(csvfile_DFD, csvfile_PA_DFD):
    list_dfd = generate_list_dfd(csvfile_DFD)
    graph_dfd = generate_dfd_graph(list_dfd)
    graph_dfd_with_data_flow_types = get_data_flow_types(graph_dfd)
    pa_dfd_graph = generate_pa_dfd_graph(graph_dfd_with_data_flow_types)
    # return graph_dfd_with_data_flow_types
    #    print(pa_dfd_graph)

    csv_columns = ['id', 'value', 'style', 'source', 'target', 'type', 'for_process', 'for_DB']
    csv_pa_dfd_file = csvfile_PA_DFD
    try:
        with open(csv_pa_dfd_file, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for key, data in pa_dfd_graph.items():
                writer.writerow(data)
    except IOError:
        print("I/O error")


# producing xml file for PA-DFD
def generate_pa_dfd_xml(csvfile_PA_DFD, xmlfile_PA_DFD):
    csvData = csv.reader(open(csvfile_PA_DFD))
    xmlData = open(xmlfile_PA_DFD, 'w')
    xmlData.write(
        '<?xml version="1.0" encoding="UTF-8"?>' + "\n" + '<mxGraphModel dx="1106" dy="1005" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="827" pageHeight="1169" math="0" shadow="0">' + "\n")
    xmlData.write(' ' + '<root>' + "\n")
    xmlData.write(' ' + '<mxCell id="0"/>' + "\n")
    xmlData.write(' ' + ' <mxCell id="1" parent="0"/>' + "\n")
    att1 = None
    att2 = None
    att3 = None
    att4 = None
    att5 = None
    vertex = 'vertex'
    parent = 'parent'
    edge = 'edge'
    rowNum = 0

    for row in csvData:
        if rowNum == 0:
            tags = row
            for i in range(len(tags)):
                if tags[i] == 'id':
                    att1 = 'id='
                elif tags[i] == 'value':
                    att2 = 'value='
                elif tags[i] == 'style':
                    att3 = 'style='
                elif tags[i] == 'source':
                    att4 = 'source='
                elif tags[i] == 'target':
                    att5 = 'target='
        else:
            style = ''
            end = '>'
            xmlData.write('  ' + '<mxCell' + ' ')
            for i in range(len(tags)):
                if i == 0:
                    xmlData.write('{} "{}" '.format(att1, str(row[i])))
                if i == 1:
                    xmlData.write('{} "{}" '.format(att2, str(row[i])))
                if i == 2:
                    if row[i] == 'shape=partialRectangle':
                        xmlData.write('{} "{};whiteSpace=wrap;left=0;right=0;" '.format(att3, str(row[i])))
                    else:
                        xmlData.write('{} "{};whiteSpace=wrap;" '.format(att3, str(row[i])))
                    style = row[i]
                    if row[i] in ['ellipse;shape=doubleEllipse', 'ellipse', 'rounded=0', 'shape=partialRectangle']:
                        xmlData.write('{}="1" {}="1" {}'.format(vertex, parent, end))
                if i == 3 and row[i] != 'null':
                    xmlData.write('{} "{}" '.format(att4, str(row[i])))
                if i == 4 and row[i] != 'null':
                    xmlData.write('{} "{}" '.format(att5, str(row[i])))
                    xmlData.write('{}="1" {}="1" >'.format(edge, parent, ))
            if style in ['ellipse;shape=doubleEllipse', 'ellipse', 'rounded=0', 'shape=partialRectangle']:
                xmlData.write("\n" + ' <mxGeometry x="560" y="480" width="100" height="100" as="geometry"/>' + "\n")
            if style in ['endArrow=classic', 'endArrow=cross']:
                xmlData.write("\n" + '<mxGeometry width="50" height="50" as="geometry">' + "\n")
                xmlData.write(' ' + '<mxPoint x="210" y="490" as="sourcePoint"/>' + "\n")
                xmlData.write(' ' + '<mxPoint x="450" y="410" as="targetPoint"/>' + "\n")
                xmlData.write(' ' + '</mxGeometry>' + "\n")
            xmlData.write(' ' + '</mxCell>' + "\n")

        rowNum = rowNum + 1

    xmlData.write('</root>' + "\n" + '</mxGraphModel>' + "\n")
    xmlData.close()


# set the four files
dfd_xml_filename = sys.argv[1]
dfd_csv_filename = sys.argv[2]
pa_dfd_csv_filename = sys.argv[3]
pa_dfd_xml_filename = sys.argv[4]

# functions
initialize(dfd_xml_filename, dfd_csv_filename)
generate_pa_dfd_csv(dfd_csv_filename, pa_dfd_csv_filename)
generate_pa_dfd_xml(pa_dfd_csv_filename, pa_dfd_xml_filename)
