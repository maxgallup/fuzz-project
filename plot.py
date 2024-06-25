#!/usr/bin/python

import os
import json

import polars as pl
import plotly.graph_objects as go
import plotly.express as px
import numpy as np


import matplotlib.pyplot as plt



def human_to_sec(human_string: str):
    minutes, seconds = human_string.split(":")
    minutes = float(minutes[:-1])
    seconds = float(seconds[:-1])

    return float(seconds + (minutes * 60))


def string_to_float(s):
    return float(s)





# def load_results(dir_path):
#     df = pl.read_json(dir_path)

#     # df = df.with_columns(pl.col('binary').map_elements(name_to_id, return_dtype=str).alias('identifier'))

#     df = df.with_columns(pl.col('execs_done').cast(pl.Float64))
#     df = df.with_columns(pl.col('execs_per_sec').cast(pl.Float64))

#     interested_cols = ['run_time', 'execs_per_sec', 'execs_done']

#     df_avg = df.group_by(pl.col('is_afl_only')).agg(pl.col(interested_cols).mean())

#     df_std = df.group_by(pl.col('is_afl_only')).agg(pl.col(interested_cols).std())

#     df_avg = df_avg.select(interested_cols).to_dict(as_series=False)


#     df_std = df_std.select(interested_cols).to_dict(as_series=False)
    

#     for key in df_avg:
#         df_avg[key] = df_avg[key][0]
    
#     for key in df_std:
#         df_std[key] = df_std[key][0]
    



#     return df_avg, df_std







def plot_runtime(our_ijon, og_ijon, afl):
    fig = go.Figure()

    fig.add_trace(go.Bar(x=our_ijon['identifier'], y=our_ijon['run_time'], name='Our IJON', marker_color='red'))
    fig.add_trace(go.Bar(x=og_ijon['identifier'], y=og_ijon['run_time'], name='Original IJON', marker_color='blue'))
    fig.add_trace(go.Bar(x=afl['identifier'], y=afl['run_time'], name='AFL++', marker_color='green'))

    # Customizing the layout
    fig.update_layout(title='Comparison of Average Runtimes', xaxis_title='Binary', yaxis_title='Average Runtime in Seconds', barmode='group', bargap=0.15, bargroupgap=0.1)

    fig.show()

def plot_execs(our_ijon, og_ijon, afl):
    fig = go.Figure()

    fig.add_trace(go.Bar(x=our_ijon['identifier'], y=our_ijon['execs_done'], name='Our IJON', marker_color='red'))
    fig.add_trace(go.Bar(x=og_ijon['identifier'], y=og_ijon['execs_done'], name='Original IJON', marker_color='blue'))
    fig.add_trace(go.Bar(x=afl['identifier'], y=afl['execs_done'], name='AFL++', marker_color='green'))

    # Customizing the layout
    fig.update_layout(title='Comparison of Average Total Executions', xaxis_title='Binary', yaxis_title='Average Total Executions', barmode='group', bargap=0.15, bargroupgap=0.1)

    fig.show()

def plot_eps(our_ijon, og_ijon, afl):
    fig = go.Figure()

    fig.add_trace(go.Bar(x=our_ijon['identifier'], y=our_ijon['execs_per_sec'], name='Our IJON', marker_color='red'))
    fig.add_trace(go.Bar(x=og_ijon['identifier'], y=og_ijon['execs_per_sec'], name='Original IJON', marker_color='blue'))
    fig.add_trace(go.Bar(x=afl['identifier'], y=afl['execs_per_sec'], name='AFL++', marker_color='green'))

    # Customizing the layout
    fig.update_layout(title='Comparison of Average Execs/Second', xaxis_title='Binary', yaxis_title='Average Execs/Second', barmode='group', bargap=0.15, bargroupgap=0.1)

    fig.show()




def plot_stats(df):

    fig = go.Figure()

    fig.add_trace(go.Bar(x=our_ijon['identifier'], y=our_ijon['execs_per_sec'], name='Our IJON', marker_color='red'))
    fig.add_trace(go.Bar(x=og_ijon['identifier'], y=og_ijon['execs_per_sec'], name='Original IJON', marker_color='blue'))
    fig.add_trace(go.Bar(x=afl['identifier'], y=afl['execs_per_sec'], name='AFL++', marker_color='green'))

    # Customizing the layout
    fig.update_layout(title='Comparison of Average Execs/Second', xaxis_title='Binary', yaxis_title='Average Execs/Second', barmode='group', bargap=0.15, bargroupgap=0.1)

    fig.show()



def plot_data(average_infos, std_infos, average_set_infos, std_set_infos):
    labels = ['run_time', 'execs_done', 'execs_per_sec']
    infos_means = [average_infos['run_time'], average_infos['execs_done'], average_infos['execs_per_sec']]
    infos_stds = [std_infos['run_time'], std_infos['execs_done'], std_infos['execs_per_sec']]
    set_infos_means = [average_set_infos['run_time'], average_set_infos['execs_done'], average_set_infos['execs_per_sec']]
    set_infos_stds = [std_set_infos['run_time'], std_set_infos['execs_done'], std_set_infos['execs_per_sec']]

    print(labels)
    print(infos_means)
    print(infos_stds)



    x = np.arange(len(labels))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width/2, infos_means, width, yerr=infos_stds, label='AFL++ Frida Mode', capsize=5)
    rects2 = ax.bar(x + width/2, set_infos_means, width, yerr=set_infos_stds, label='AFL++ Frida Mode + IJON SET', capsize=5)

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_xlabel('Metrics')
    ax.set_ylabel('Values')
    ax.set_title('Metrics')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_yscale('log')
    ax.legend()

    fig.tight_layout()

    plt.show()




def load_latest_results(res_dir):
    prog_names = [
        'mario-easy',
        'mario-mid',
        'mario-hard',
        'maze-small',
        'maze-big'
    ]
    


    def name_to_id(some_name):
        for p in prog_names:
            if p in some_name:
                return p
        return ""


    def name_to_type(name):
        if "afl" in name:
            return "AFL"
        if "ijon" in name:
            return "IJON Original"
        if "new" in name:
            return "IJON New"


    dir_path = f"./{res_dir}/results"
    files = os.listdir(dir_path)
    # Sort the files by modification time
    files.sort(key=lambda x: os.path.getmtime(os.path.join(dir_path, x)))

    if not files:
        print("./results is empty!")
        exit(1)

    # Open the most recently modified file
    most_recent_file = files[-1]

    df = pl.read_json(os.path.join(dir_path, most_recent_file))

    df = df.with_columns(pl.col('binary').map_elements(name_to_id, return_dtype=str).alias('identifier'))
    
    df = df.with_columns(pl.col('binary').map_elements(name_to_type, return_dtype=str).alias('type'))



    df = df.with_columns(pl.col('execs_done').cast(pl.Float64))
    df = df.with_columns(pl.col('execs_per_sec').cast(pl.Float64))
    df = df.with_columns(pl.col('run_time').cast(pl.Float64))

    interested_cols = ['run_time', 'execs_per_sec', 'execs_done']

    df_avg = df.group_by(pl.col(['binary', 'identifier', 'type'])).agg(pl.col(interested_cols).mean())
    df_std = df.group_by(pl.col(['binary', 'identifier', 'type'])).agg(pl.col(interested_cols).std())
    df_len = df.group_by(pl.col(['binary', 'identifier', 'type'])).agg(pl.col(interested_cols).len())

    return df_avg, df_std, df_len



def plot_game_bar(df_avg, df_std, df_len, col_name):
    fig = px.bar(df_avg, x="identifier", y=col_name, color=df_avg['type'], title="testing",
    error_x=df_std['identifier'], error_y=df_std[col_name])

    # Customizing the layout
    fig.update_layout(title=f'Comparison of {col_name}', xaxis_title='Programs', yaxis_title=col_name, barmode='group', bargap=0.15, bargroupgap=0.1)

    fig.show()


def plot_games():

    old_avg, old_std, old_len = load_latest_results("eval-old-ijon")
    new_avg, new_std, new_len = load_latest_results("eval-new-ijon")

    df_avg = pl.concat([old_avg, new_avg])
    df_std = pl.concat([old_std, new_std])
    df_len = pl.concat([old_len, new_len])

    print(df_avg, df_std, df_len)

    plot_game_bar(df_avg, df_std, df_len, 'run_time')

def main():


    plot_games()


    # plot_svg()


    
    # afl = load_results("./afl++/results/afl.json")
    # our_ijon = load_results("./afl++/results/our_ijon.json")
    # og_ijon = load_results("./ijon-original/ijon-experiment/results/original_ijon.json")


    # data = load_latest_results('./wip/svg2ass/results/')
    # ijon_avg, ijon_std = load_results('./wip/svg2ass/results/ijon.json')
    # afl_avg, afl_std = load_results('./wip/svg2ass/results/afl.json')

    # average_infos = afl_avg
    # std_infos = afl_std

    # average_set_infos = ijon_avg
    # std_set_infos = ijon_std

    # plot_data(average_infos, std_infos, average_set_infos, std_set_infos)
    # print(afl)

    # plot_runtime(our_ijon.to_pandas(), og_ijon.to_pandas(), afl.to_pandas())
    # plot_execs(our_ijon.to_pandas(), og_ijon.to_pandas(), afl.to_pandas())
    # plot_eps(our_ijon.to_pandas(), og_ijon.to_pandas(), afl.to_pandas())


if __name__ == '__main__':
    main()
