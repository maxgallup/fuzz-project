#!/usr/bin/python

import os
import json

import polars as pl
import plotly.graph_objects as go
import plotly.express as px


prog_names = [
    'mario-easy',
    'mario-mid',
    'mario-hard',
    'maze-small',
    'maze-big',
]

def human_to_sec(human_string: str):
    minutes, seconds = human_string.split(":")
    minutes = float(minutes[:-1])
    seconds = float(seconds[:-1])

    return float(seconds + (minutes * 60))


def string_to_float(s):
    return float(s)


def name_to_id(some_name):
    for p in prog_names:
        if p in some_name:
            return p
    return null


def load_results(dir_path):
    # # Get a list of files in the directory
    # files = os.listdir(dir_path)
    # # Sort the files by modification time
    # files.sort(key=lambda x: os.path.getmtime(os.path.join(dir_path, x)))
    # # Open the most recently modified file
    # most_recent_file = files[-1]
    # df = pl.read_json(os.path.join(dir_path, most_recent_file))

    df = pl.read_json(dir_path)

    df = df.with_columns(pl.col('run_time_hms').map_elements(human_to_sec, return_dtype=float).alias('run_time'))

    df = df.with_columns(pl.col('binary').map_elements(name_to_id, return_dtype=str).alias('identifier'))

    df = df.with_columns(pl.col('execs_done').cast(pl.Float64))
    df = df.with_columns(pl.col('execs_per_sec').cast(pl.Float64))

    df = df.group_by(pl.col('identifier')).agg(pl.col(['run_time', 'execs_per_sec', 'execs_done']).mean())

    custom_order = {val: idx for idx, val in enumerate(prog_names)}
    

    # Sorting the DataFrame
    df = df.sort(pl.col("identifier").map_dict(custom_order), descending=[True])

    return df




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




def main():
    afl = load_results("./afl++/results/afl.json")
    our_ijon = load_results("./afl++/results/our_ijon.json")
    og_ijon = load_results("./ijon-original/ijon-experiment/results/original_ijon.json")


    # print(afl)
    plot_runtime(our_ijon.to_pandas(), og_ijon.to_pandas(), afl.to_pandas())
    plot_execs(our_ijon.to_pandas(), og_ijon.to_pandas(), afl.to_pandas())
    plot_eps(our_ijon.to_pandas(), og_ijon.to_pandas(), afl.to_pandas())


if __name__ == '__main__':
    main()
