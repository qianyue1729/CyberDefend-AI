import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import os
import openai

# 设置OpenAI API密钥
openai.api_key = os.getenv("OPENAI_API_KEY")

# 设定日志文件路径
log_file_path = 'log_data/dns_log.csv'  # 更新路径

st.set_page_config(page_title="DNS Dashboard", page_icon=":bar_chart:", layout="wide")

def load_data():
    """加载CSV文件数据"""
    if os.path.exists(log_file_path):
        try:
            df = pd.read_csv(log_file_path, parse_dates=['Timestamp'], na_values=['', 'NA', 'NaN'])
            return df
        except Exception as e:
            st.error(f"Error reading the log file: {e}")
            return pd.DataFrame()
    else:
        st.error(f"Log file {log_file_path} does not exist.")
        return pd.DataFrame()

def get_domain_analysis(domain):
    """使用OpenAI API对域名进行详细分析和解释"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": f"Analyze the following domain for potential threats and unusual activity: {domain}. Provide a detailed explanation and recommendations."}
            ]
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        st.error(f"Error analyzing domain: {e}")
        return "Error"

def generate_summary_report(df):
    """生成网络活动的总结报告"""
    allowed_packets = len(df[df['DNS Response Code'] == 0])
    blocked_packets = len(df[df['DNS Response Code'] != 0])
    most_common_domain = df['Queried Domain'].value_counts().idxmax() if not df['Queried Domain'].empty else "N/A"
    most_common_category = df['Category'].value_counts().idxmax() if not df['Category'].empty else "N/A"

    summary = f"""
    **Activity Summary:**

    - Total Packets: {len(df)}
    - Allowed Packets: {allowed_packets}
    - Blocked Packets: {blocked_packets}
    - Most Queried Domain: {most_common_domain}
    - Most Common Category: {most_common_category}
    """

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": f"Generate a summary report based on the following data:\n{summary}"}
            ]
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        st.error(f"Error generating summary report: {e}")
        return summary

def app():
    st.title('DNS Traffic Dashboard')

    df = load_data()

    if df.empty:
        st.write("No data available.")
        return

    # 显示统计信息
    total_packets = len(df)
    allowed_packets = len(df[df['DNS Response Code'] == 0])
    blocked_packets = len(df[df['DNS Response Code'] != 0])

    total_card, allowed_card, blocked_card = st.columns(3)
    total_card.metric("Total Packets", total_packets)
    allowed_card.metric("Allowed Packets", allowed_packets)
    blocked_card.metric("Blocked Packets", blocked_packets)

    # 绘制整个数据集的网络流量折线图
    df_resampled = df.set_index('Timestamp').resample('5Min').count()

    st.subheader('Network Traffic')
    st.line_chart(df_resampled['Queried Domain'])

    # 最新DNS查询表格和攻击类型饼图
    latest_queries_table, query_type_pie = st.columns(2)

    latest_queries_table.subheader('Latest DNS Queries')
    latest_queries_table.dataframe(df.tail(10)[['Timestamp', 'Queried Domain', 'Device IP', 'Source MAC', 'Destination IP', 'Destination MAC', 'Protocol', 'Packet Size', 'DNS Response Code', 'Category', 'Query Count']])

    query_type_pie.subheader('Types of Queries')
    
    # 大类数据
    df['Main Category'] = df['Category'].apply(lambda x: x.split('/')[0] if pd.notnull(x) else "Unknown")  # 生成大类
    df_main_categories = df['Main Category'].value_counts()
    
    fig = go.Figure()

    # 添加大类饼图
    fig.add_trace(go.Pie(labels=df_main_categories.index, values=df_main_categories, name="Main Category"))

    # 添加小类饼图（初始不可见）
    for main_category in df_main_categories.index:
        subcategories = df[df['Main Category'] == main_category]['Category'].value_counts()
        fig.add_trace(go.Pie(labels=subcategories.index, values=subcategories, name=main_category, visible=False))

    # 创建按钮来切换视图
    buttons = []
    buttons.append(dict(label='Main Categories',
                        method='update',
                        args=[{'visible': [True] + [False] * len(df_main_categories.index)},
                              {'title': 'Main Categories'}]))

    for i, main_category in enumerate(df_main_categories.index):
        visible_array = [False] * (len(df_main_categories.index) + len(df_main_categories.index))
        visible_array[i + 1] = True
        buttons.append(dict(label=main_category,
                            method='update',
                            args=[{'visible': visible_array},
                                  {'title': main_category}]))

    fig.update_layout(updatemenus=[dict(type='dropdown', direction='down', buttons=buttons, x=1, y=1, showactive=True)])

    query_type_pie.plotly_chart(fig)

    # 域名查询和分析功能
    st.subheader('Domain Lookup and Analysis')
    domain_lookup = st.text_input('Enter a domain to lookup and analyze', '')
    if domain_lookup:
        domain_info = df[df['Queried Domain'].str.contains(domain_lookup, case=False, na=False)]
        if not domain_info.empty:
            st.write(f"Results for '{domain_lookup}':")
            st.dataframe(domain_info[['Timestamp', 'Queried Domain', 'Device IP', 'Source MAC', 'Destination IP', 'Destination MAC', 'Protocol', 'Packet Size', 'DNS Response Code', 'Category', 'Query Count']])
            st.write("Detailed Analysis from OpenAI:")
            domain_analysis = get_domain_analysis(domain_lookup)
            st.write(domain_analysis)
        else:
            st.write(f"No results found for '{domain_lookup}'.")

    # 生成报告
    st.subheader('Generate Summary Report')
    if st.button('Generate Summary Report'):
        summary_report = generate_summary_report(df)
        st.markdown(summary_report)

if __name__ == '__main__':
    app()
