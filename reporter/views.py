from io import BytesIO

import os
from django.shortcuts import render, redirect, render_to_response

from reporter.PdfPrinter import PdfPrinter
from reporter.Common import Common

from reporter.forms import MalwareFileForm, MalwareDependenciesForm, MalwareCharacteristicForm, AnalysisFindingsForm, \
    SupportingFiguresForm, ReportForm
from reporter.models import Report
from django.core.files.storage import FileSystemStorage
import pefile


def index_view(request, template_name='reporter/index.html'):
    return render(request, template_name)


def list_view(request, template_name='reporter/list.html'):
    all_reports = Report.objects.all()
    return render(request, template_name, {'reports': all_reports})


def delete_view(request):
    report_name = request.POST.get("report_name", "")
    report = Report.objects.get(report_name=report_name)

    if request.method == 'POST':
        report.delete()

    return redirect('reporter:list')


def help_view(request, template_name='reporter/help.html'):
    return render(request, template_name)


def new_report_view(request, template_name='reporter/report_info.html'):
    report_form = ReportForm()
    malware_info_form = MalwareFileForm()
    malware_dependencies_form = MalwareDependenciesForm()
    malware_characteristic_form = MalwareCharacteristicForm()
    analysis_findings_form = AnalysisFindingsForm()
    supporting_figures_form = SupportingFiguresForm()

    return render(request, template_name, {'report_form': report_form,
                                           'malware_info_form': malware_info_form,
                                           'malware_dependencies_form': malware_dependencies_form,
                                           'malware_characteristic_form': malware_characteristic_form,
                                           'analysis_findings_form': analysis_findings_form,
                                           'supporting_figures_form': supporting_figures_form})


def list_of_all_reports_view(request, template_name='reporter/list.html'):
    if request.POST:
        analysis_findings_form, malware_characteristic_form, malware_dependencies_form, malware_info_form, report_form, supporting_figures_form = Common.get_data_from_request(
            request)

        if report_form.is_valid() and malware_info_form.is_valid():
            report = report_form.save(commit=False)
            malware_file = malware_info_form.save(commit=False)
            malware_dependencies = malware_dependencies_form.save(commit=False)
            malware_characteristic = malware_characteristic_form.save(commit=False)
            analysis_findings = analysis_findings_form.save(commit=False)
            supporting_figures = supporting_figures_form.save(commit=False)

            Common.save_malware_info_segments(analysis_findings, malware_characteristic, malware_dependencies,
                                              supporting_figures)
            Common.save_malware_file_info(analysis_findings, malware_characteristic, malware_dependencies, malware_file,
                                          supporting_figures)
            Common.save_report(malware_file, report)

            all_reports = Report.objects.all()
            return render(request, template_name, {'reports': all_reports})

    return redirect('reporter:empty_form')


def generate_pdf(request):
    if 'pdf' in request.POST:
        report_name = request.POST.get("report_name", "")

        response = Common.create_file_attachment_response()
        buffer = BytesIO()

        report_pdf = PdfPrinter(buffer, 'A4')
        pdf = report_pdf.report('Malware Analysis Report', report_name)

        response.write(pdf)

        return response


def simple_upload(request, template_name='reporter/report_info.html'):
    if request.FILES.get('myfile') is None:
        return redirect('reporter:empty_form')

    if request.POST and request.FILES.get('myfile', True):
        myfile = request.FILES['myfile']
        fs = FileSystemStorage()
        fs.save(myfile.name, myfile)
        path = fs.location + '\\' + myfile.name

        pe = pefile.PE(path)
        report_form = ReportForm()
        report_form.fields['report_name'].initial = myfile.name + ' report'
        report_form.fields['additional_findings'].initial = get_additional_info(pe)

        malware_info_form = MalwareFileForm()
        malware_info_form.fields['malware_name'].initial = myfile.name
        malware_info_form.fields['size'].initial = os.path.getsize(path)
        malware_info_form.fields['found_place'].initial = 'Path to file: ' + path

        malware_dependencies_form = MalwareDependenciesForm()
        malware_dependencies_form.fields['support_OS_version'].initial = 'Windows'

        malware_characteristic_form = MalwareCharacteristicForm()
        analysis_findings_form = AnalysisFindingsForm()
        supporting_figures_form = SupportingFiguresForm()

        return render(request, template_name, {'report_form': report_form,
                                               'malware_info_form': malware_info_form,
                                               'malware_dependencies_form': malware_dependencies_form,
                                               'malware_characteristic_form': malware_characteristic_form,
                                               'analysis_findings_form': analysis_findings_form,
                                               'supporting_figures_form': supporting_figures_form})

    return redirect('reporter:empty_form')


def get_additional_info(pe):
    additional_findings = 'Entry point: ' + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) + '\nImage base: ' + hex(
        pe.OPTIONAL_HEADER.ImageBase) + '\n\n---FILE SECTIONS---'
    for section in pe.sections:
        additional_findings += '\nName: ' + str(section.Name)
        additional_findings += '\nVirtual address: ' + hex(section.VirtualAddress)
        additional_findings += '\nSize of raw data: ' + str(section.SizeOfRawData)
    return additional_findings
