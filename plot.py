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





# #!/usr/bin/python

# import os
# import json

# import polars as pl
# import plotly.graph_objects as go
# import plotly.express as px

# from plotly.subplots import make_subplots

# prog_names = [
#     'mario-easy',
#     'mario-mid',
#     'mario-hard',
#     'maze-small',
#     'maze-big',
# ]

# def human_to_sec(human_string: str):
#     minutes, seconds = human_string.split(":")
#     minutes = float(minutes[:-1])
#     seconds = float(seconds[:-1])

#     return float(seconds + (minutes * 60))


# def string_to_float(s):
#     return float(s)


# def name_to_id(some_name):
#     for p in prog_names:
#         if p in some_name:
#             return p
#     return null


# def load_results(dir_path):
#     # # Get a list of files in the directory
#     # files = os.listdir(dir_path)
#     # # Sort the files by modification time
#     # files.sort(key=lambda x: os.path.getmtime(os.path.join(dir_path, x)))
#     # # Open the most recently modified file
#     # most_recent_file = files[-1]
#     # df = pl.read_json(os.path.join(dir_path, most_recent_file))

#     df = pl.read_json(dir_path)

#     df = df.with_columns(pl.col('run_time_hms').map_elements(human_to_sec, return_dtype=float).alias('run_time'))

#     df = df.with_columns(pl.col('binary').map_elements(name_to_id, return_dtype=str).alias('identifier'))

#     df = df.with_columns(pl.col('execs_done').cast(pl.Float64))
#     df = df.with_columns(pl.col('execs_per_sec').cast(pl.Float64))

#     df = df.group_by(pl.col('identifier')).agg(pl.col(['run_time', 'execs_per_sec', 'execs_done']).mean())

#     custom_order = {val: idx for idx, val in enumerate(prog_names)}

#     # Sorting the DataFrame
#     df = df.sort(pl.col("identifier").map_dict(custom_order), descending=[True])

#     return df


# def load_raw(dir_path):
#     df = pl.read_json(dir_path)

#     df = df.with_columns(pl.col('run_time_hms').map_elements(human_to_sec, return_dtype=float).alias('run_time'))

#     df = df.with_columns(pl.col('binary').map_elements(name_to_id, return_dtype=str).alias('identifier'))

#     df = df.with_columns(pl.col('execs_done').cast(pl.Float64))
#     df = df.with_columns(pl.col('execs_per_sec').cast(pl.Float64))

#     custom_order = {val: idx for idx, val in enumerate(prog_names)}

#     # Sorting the DataFrame
#     df = df.sort(pl.col("identifier").map_dict(custom_order), descending=[True])
#     return df


# def plot(our_ijon, og_ijon, afl):
#     fig = make_subplots(rows=3, cols=1)

#     fig.add_trace(go.Bar(x=our_ijon['identifier'], y=our_ijon['run_time'], name='Our IJON run_time', marker_color='red'), row=1, col=1)
#     fig.add_trace(go.Bar(x=og_ijon['identifier'], y=og_ijon['run_time'], name='Original IJON run_time', marker_color='blue'), row=1, col=1)
#     fig.add_trace(go.Bar(x=afl['identifier'], y=afl['run_time'], name='AFL++ run_time', marker_color='green'), row=1, col=1)


#     # fig.update_layout(title='Comparison Runtime', xaxis_title='Binary', yaxis_title='Runtime', barmode='group', bargap=0.15, bargroupgap=0.1)

#     fig.add_trace(go.Bar(x=our_ijon['identifier'], y=our_ijon['execs_done'], name='Our IJON execs_done', marker_color='red'), row=2, col=1)
#     fig.add_trace(go.Bar(x=og_ijon['identifier'], y=og_ijon['execs_done'], name='Original IJON execs_done', marker_color='blue'), row=2, col=1)
#     fig.add_trace(go.Bar(x=afl['identifier'], y=afl['execs_done'], name='AFL++ execs_done', marker_color='green'), row=2, col=1)


#     # fig.update_layout(title='Comparison Total Executions', xaxis_title='Binary', yaxis_title='Total Executions', barmode='group', bargap=0.15, bargroupgap=0.1)

#     fig.add_trace(go.Bar(x=our_ijon['identifier'], y=our_ijon['execs_per_sec'], name='Our IJON execs_per_sec', marker_color='red'), row=3, col=1)
#     fig.add_trace(go.Bar(x=og_ijon['identifier'], y=og_ijon['execs_per_sec'], name='Original IJON execs_per_sec', marker_color='blue'), row=3, col=1)
#     fig.add_trace(go.Bar(x=afl['identifier'], y=afl['execs_per_sec'], name='AFL++ execs_per_sec', marker_color='green'), row=3, col=1)

#     # Customizing the layout
#     # fig.update_layout(title='Comparison of Average Execs/Second', xaxis_title='Binary', yaxis_title='Executions/Second', barmode='group', bargap=0.15, bargroupgap=0.1)

#     fig.show()



# def plot_histograms(afl, our_ijon):
#     fig = make_subplots(rows=3, cols=3)

#     fig.add_trace(
#         go.Histogram(x=afl['run_time'], nbinsx=100, name=f"afl-run_time {len(afl['run_time'])}"),
#         row=1, col=1
#     )

#     fig.add_trace(
#         go.Histogram(x=afl['execs_per_sec'], nbinsx=100, name=f"afl-execs_per_sec {len(afl['run_time'])}"),
#         row=2, col=1
#     )

#     fig.add_trace(
#         go.Histogram(x=afl['execs_done'], nbinsx=100, name=f"afl-execs_done {len(afl['run_time'])}"),
#         row=3, col=1
#     )

#     fig.add_trace(
#         go.Histogram(x=our_ijon['run_time'], nbinsx=100, name=f"our_ijon-run_time {len(our_ijon['run_time'])}"),
#         row=1, col=2
#     )

#     fig.add_trace(
#         go.Histogram(x=our_ijon['execs_per_sec'], nbinsx=100, name=f"our_ijon-execs_per_sec {len(our_ijon['run_time'])}"),
#         row=2, col=2
#     )

#     fig.add_trace(
#         go.Histogram(x=our_ijon['execs_done'], nbinsx=100, name=f"our_ijon-execs_done {len(our_ijon['run_time'])}"),
#         row=3, col=2
#     )


#     fig.update_layout(height=600, width=800, title_text="Histograms")
#     fig.show()


# def plot_histogram(df):

#     fig = px.histogram(df, x=df['run_time'])
#     fig.show()


# def main():
#     afl = load_results("./afl++/results/afl.json")
#     our_ijon = load_results("./afl++/results/our_ijon.json")
#     og_ijon = load_results("./ijon-original/ijon-experiment/results/original_ijon.json")

#     afl_raw = load_raw("./afl++/results/afl.json")
#     our_ijon_raw = load_raw("./afl++/results/our_ijon.json")
#     og_ijon_raw = load_raw("./ijon-original/ijon-experiment/results/original_ijon.json")


#     # print(afl)

#     # plot_histograms(afl_raw.filter(pl.col('identifier') == "mario-easy"), our_ijon_raw.filter(pl.col('identifier') == "mario-easy"))
#     # plot_histograms(afl_raw.filter(pl.col('identifier') == "mario-mid"), our_ijon_raw.filter(pl.col('identifier') == "mario-mid"))
#     # plot_histograms(afl_raw.filter(pl.col('identifier') == "mario-hard"), our_ijon_raw.filter(pl.col('identifier') == "mario-hard"))
#     # plot_histograms(afl_raw.filter(pl.col('identifier') == "maze-small"), our_ijon_raw.filter(pl.col('identifier') == "maze-small"))
#     # plot_histograms(afl_raw.filter(pl.col('identifier') == "maze-big"), our_ijon_raw.filter(pl.col('identifier') == "maze-big"))


#     plot(our_ijon.to_pandas(), og_ijon.to_pandas(), afl.to_pandas())
    


# if __name__ == '__main__':
#     main()
