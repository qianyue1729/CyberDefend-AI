import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import os

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

st.set_page_config(page_title="Dashboard",
                   page_icon=":bar_chart:",
                   layout="wide")


def app():
    st.title('Dashboard')

    log_file_path = ( 'log_data/log.csv')
    df = pd.read_csv(log_file_path)

    df['date'] = pd.to_datetime(df['date'])
    df.set_index('date', inplace=True)

    # Cards
    total_packets = len(df)
    allowed_packets = len(df[df['status'] == 'ALLOW'])
    blocked_packets = len(df[df['status'] == 'BLOCK'])

    total_card, allowed_card, blocked_card = st.columns((1, 1, 1))
    total_card.metric("Total Packets", total_packets)
    allowed_card.metric("Allowed Packets", allowed_packets)
    blocked_card.metric("Blocked Packets", blocked_packets)

    # Line Chart
    now = datetime.now()
    one_day_ago = now - timedelta(hours=24)
    df_last_24_hours = df[df.index > one_day_ago]
    df_resampled = df_last_24_hours[df_last_24_hours['status'].isin(
        ['ALLOW', 'ALERT'])].resample('5Min').count()

    st.subheader('Network Traffic in the Last 24 Hours')
    st.line_chart(df_resampled)

    # table and pie
    latest_blocked_domain_table, type_of_attack_pie = st.columns(2)

    # Display the table of 10 latest blocked or alerted domains
    latest_blocked_domain_table.subheader('Latest Blocked or Alerted Domains')
    df_blocked_alerted = df[df['status'].isin(['BLOCK', 'ALERT'])][[
        'domain', 'source_ip', 'prediction']]
    latest_blocked_domain_table.table(df_blocked_alerted.tail(10))

    # Display the pie chart of types of attacks
    type_of_attack_pie.subheader('Types of Attacks')
    df_attacks = df['prediction'].value_counts()
    fig, ax = plt.subplots(figsize=(5, 2.6))
    ax.pie(df_attacks, 
           labels=df_attacks.index.tolist(),
           autopct='%1.1f%%', startangle=90)
    ax.axis('equal')
    type_of_attack_pie.pyplot(fig)


if __name__ == '__main__':
    app()
