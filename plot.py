
import os
import json

import polars as pl
#!/usr/bin/python
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.io as pio
import numpy as np


def load_latest_game_results(res_dir, prog_names):

    def name_to_id(some_name):
        for p in prog_names:
            if p in some_name:
                return p
        return ""

    def name_to_type(name):
        if "afl" in name:
            return "AFL++"
        if "ijon" in name:
            return "IJON-Original"
        if "new" in name:
            return "IJON-Frida"


    files = os.listdir(res_dir)
    # Sort the files by modification time
    files.sort(key=lambda x: os.path.getmtime(os.path.join(res_dir, x)))

    if not files:
        print("./results is empty!")
        exit(1)

    # Open the most recently modified file
    most_recent_file = files[-1]

    df = pl.read_json(os.path.join(res_dir, most_recent_file))

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
    fig = px.bar(df_avg, x="identifier", y=col_name, color=df_avg['type'],
    error_x=df_std['identifier'], error_y=df_std[col_name])

    custom_title = f'Fuzzing terminated upon first crash'
    if col_name == 'execs_done':
        custom_title = 'Average Total Executions' 
    elif col_name == 'execs_per_sec':
        custom_title = 'Average Executions per Second'
    elif col_name == 'run_time':
        custom_title = 'Average Run Time (until first crash)'

    # Customizing the layout
    fig.update_layout(title=custom_title, xaxis_title='Programs', yaxis_title=col_name, barmode='group', bargap=0.15, bargroupgap=0.1)

    # fig.show()
    
    pio.write_image(fig, f"./plots/game-{col_name}.png",scale=6, width=1155, height=600)
    # fig.write_image(f"./plots/game-{col_name}.png")



def plot_games():

    prog_names = [
        'mario-easy',
        'mario-mid',
        'mario-hard',
        'maze-small',
        'maze-big'
    ]

    order_array = [
        'maze-small-ijon',
        './binaries/maze-small-afl',
        './binaries/maze-small-new',
        'maze-big-ijon',
        './binaries/maze-big-afl',
        './binaries/maze-big-new',
        'mario-easy-ijon',
        './binaries/mario-easy-afl',
        './binaries/mario-easy-new',
        'mario-mid-ijon',
        './binaries/mario-mid-new',
        'mario-hard-ijon',
        './binaries/mario-hard-new',
    ]


    old_avg, old_std, old_len = load_latest_game_results("./eval-old-ijon/results", prog_names)
    new_avg, new_std, new_len = load_latest_game_results("./eval-new-ijon/results", prog_names)

    df_avg = pl.concat([old_avg, new_avg])
    df_std = pl.concat([old_std, new_std])
    df_len = pl.concat([old_len, new_len])

    custom_order = {val: idx for idx, val in enumerate(order_array)}
    df_avg = df_avg.sort(pl.col("binary").map_dict(custom_order), descending=[True])
    df_std = df_std.sort(pl.col("binary").map_dict(custom_order), descending=[True])
    df_len = df_len.sort(pl.col("binary").map_dict(custom_order), descending=[True])

    print(df_avg, df_std, df_len)

    plot_game_bar(df_avg, df_std, df_len, 'run_time')
    plot_game_bar(df_avg, df_std, df_len, 'execs_per_sec')
    plot_game_bar(df_avg, df_std, df_len, 'execs_done')



def load_latest_svg_results(res_dir):
    prog_names = [
        'svg2ass-afl',
        'svg2ass-new',
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


    files = os.listdir(res_dir)
    # Sort the files by modification time
    files.sort(key=lambda x: os.path.getmtime(os.path.join(res_dir, x)))

    if not files:
        print("./results is empty!")
        exit(1)

    # Open the most recently modified file
    most_recent_file = files[-1]

    df = pl.read_json(os.path.join(res_dir, most_recent_file))
    df = df.with_columns(pl.col('binary').map_elements(name_to_id, return_dtype=str).alias('identifier'))    
    df = df.with_columns(pl.col('binary').map_elements(name_to_type, return_dtype=str).alias('type'))
    df = df.with_columns(pl.col('execs_done').cast(pl.Float64))
    df = df.with_columns(pl.col('execs_per_sec').cast(pl.Float64))
    df = df.with_columns(pl.col('run_time').cast(pl.Float64))

    interested_cols = ['run_time', 'execs_per_sec', 'execs_done']

    df_avg = df.group_by(pl.col(['binary', 'identifier', 'type'])).agg(pl.col(interested_cols).mean()).to_pandas()
    df_std = df.group_by(pl.col(['binary', 'identifier', 'type'])).agg(pl.col(interested_cols).std()).to_pandas()
    df_len = df.group_by(pl.col(['binary', 'identifier', 'type'])).agg(pl.col(interested_cols).len()).to_pandas()

    return df_avg, df_std, df_len



def plot_svg2ass():
    svg_avg, svg_std, svg_len = load_latest_svg_results("./eval-svg2ass/results")

    print(svg_avg)
    # fig = go.Figure()

    fig = make_subplots(rows=1, cols=3)

    def get_color(type_name):
        if 'AFL' in type_name:
            return 'red'
        else:
            return 'blue'


    for i, row in svg_avg.iterrows():
        fig.add_trace(go.Bar(
            x=['Run Time (Seconds)'],
            y=[row['run_time']],
            marker_color=get_color(row['type']),
            error_y=dict(
                type='data',
                symmetric=True,
                array=[svg_std.loc[i, 'run_time']]
            ), showlegend=False
        ),  row=1, col=1)
    
    for i, row in svg_avg.iterrows():
        fig.add_trace(go.Bar(
            x=['Total Executions'],
            y=[row['execs_done']],
            marker_color=get_color(row['type']),
            error_y=dict(
                type='data',
                symmetric=True,
                array=[svg_std.loc[i, 'execs_done']]
            ), showlegend=False
        ),  row=1, col=2)
    
    for i, row in svg_avg.iterrows():
        fig.add_trace(go.Bar(
            x=['Executions / Second'],
            y=[row['execs_per_sec']],
            marker_color=get_color(row['type']),
            error_y=dict(
                type='data',
                symmetric=True,
                array=[svg_std.loc[i, 'execs_per_sec']]
            ), showlegend=False
        ),  row=1, col=3)

    # fig.update_yaxes(type="log")

    fig.add_annotation(
        x=1.0,  # Same position as the first legend entry
        y=1.16,  # Different vertical position for the second legend entry
        showarrow=False,
        text="<span style='color:red;'>AFL++ Frida</span><br><span style='color:blue;'>AFL++ Frida IJON-SET</span>",
        font=dict(size=15),
        bgcolor="white",
        bordercolor="black",
        borderwidth=0.2,
        borderpad=4,
        align="left",
        xref="paper",
        yref="paper"
    )


    fig.update_layout(barmode='group', title_text='Comparison to standard AFL++')

    pio.write_image(fig, f"./plots/svg2ass.png",scale=6, width=600, height=550)
    # fig.show()


if __name__ == '__main__':
    # plot_games()
    plot_svg2ass()
